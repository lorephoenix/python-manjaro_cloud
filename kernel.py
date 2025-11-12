#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# File              : kernel.py
# Date              : 2025-11-11 10:09:41
# Last Modified time: 2025-11-11 12:17:40
#
# Author:           : Christophe Vermeren <lore.phoenix@gmail.com>
# @License          : MIT License

# =====================================================
# Standard library imports
# =====================================================
from dataclasses import dataclass
from typing import Any, Dict, Final, List, Optional
import argparse
import platform
import requests
import sys

# =====================================================
# Third-party imports
# =====================================================
from loguru import logger
import certifi  # SSL certificates for secure requests
import colorama


# =====================================================
# My imports
# =====================================================
from loghandler import LogSettings

# =====================================================
# Constants
# =====================================================
DEFAULT_TIMEOUT: Final[int] = 5
KERNEL_URL: Final[str] = "https://www.kernel.org/releases.json"


# =====================================================
# Custom Exceptions
# =====================================================
class DownloadError(Exception):
    """Base class for download-related errors."""


class NetworkError(DownloadError):
    """Raised when a network operation fails."""


# =====================================================
# Data Model
# =====================================================
# slots=True Prevents dynamic attribute assignment, memory-efficient
# frozen=True Makes the instances of the class immutable after creation.
@dataclass(slots=True, frozen=True)
class KernelConfig:
    """
    Immutable configuration for kernel version fetching.

    Attributes:
        os_info (Optional[str]): Detected operating system identifier.
        verbose (int): Verbosity level (0–3).
    """
    verbose: int = 0
    verify_ssl: bool = True


class LinuxKernelVersions:
    """
    A class to fetch and manage the latest Linux kernel versions.
    Provides properties to get and set the latest stable and longterm (LTS)
    kernel versions.
    """

    def __init__(self, config: KernelConfig) -> None:
        """
        Initialize the class with a custom timeout for HTTP requests.

        Args:
            config (KernelConfig): Configuration object for verbosity and SSL.
        """
        self.config = config
        self.session = requests.Session()
        self.session.verify = certifi.where() if config.verify_ssl else False
        self._stable_version: Optional[str] = None
        self._longterm_version: Optional[str] = None
        logger.trace(f"LinuxKernelVersions initialized: {self}")

    def __str__(self):
        ''' This method returns the string representation of the object.
            This method is called when print() or str() function is invoked on
            an object.
        '''
        return str(self.__class__) + ": " + str(self.__dict__)

    # P r o p e r t i e s
    #
    # A property is a special kind of class attribute that lets you control
    # access to an internal variable — typically to encapsulate logic around
    # getting, setting, or deleting its value

    @property
    def longterm_version(self) -> Optional[str]:
        """
        Get the latest longterm (LTS) kernel version.
        Fetches the latest versions if not already fetched.

        Returns:
            Optional[str]: Latest longterm kernel version.
        """
        if self._longterm_version is None:
            self.fetch_latest_versions()
        return self._longterm_version

    @longterm_version.setter
    def longterm_version(self, value: str) -> None:
        """
        Set the latest longterm (LTS) kernel version.

        Args:
            value (str): Version string to set.
        """
        self._longterm_version = value

    @property
    def stable_version(self) -> Optional[str]:
        """
        Get the latest stable kernel version.
        Fetches the latest versions if not already fetched.

        Returns:
            Optional[str]: Latest stable kernel version.
        """
        if self._stable_version is None:
            self.fetch_latest_versions()
        return self._stable_version

    @stable_version.setter
    def stable_version(self, value: str) -> None:
        """
        Set the latest stable kernel version.

        Args:
            value (str): Version string to set.
        """
        self._stable_version = value

    # p r o t e c t e d   m e t h o d s
    #
    # The underscore (_) signals to other developers that this method is
    # intended for internal use within the class or its subclasses. It is not
    # meant to be accessed directly from outside the class.

    def _fetch_kernel_data(self) -> Dict[str, Any]:
        """
        Fetches the kernel version data from the official kernel.org API.

        Returns:
            Dict[str, Any]: JSON response containing kernel version data.

        Raises:
            NetworkError: If the HTTP request fails.
        """
        try:
            response = self.session.get(
                KERNEL_URL,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            raise NetworkError(
                f"Error fetching kernel data: {err}")
        else:
            logger.success(f"The URL is reachable: {KERNEL_URL}")
        return response.json()

    @staticmethod
    def _filter_longterm_releases(
        releases: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Filters the releases list to only include longterm (LTS) releases.

        Args:
            releases (List[Dict[str, Any]]): List of release dictionaries.

        Returns:
            List[Dict[str, Any]]: Filtered list of longterm releases.
        """
        return [r for r in releases if r.get("moniker") == "longterm"]

    @staticmethod
    def _sort_releases_by_version(
            releases: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Sorts releases by version in descending order.
        Correctly handles version strings in function of major, minor, patch.

        Args:
            releases (List[Dict[str, Any]]): List of release dictionaries.

        Returns:
            List[Dict[str, Any]]: Sorted list of releases.
        """
        def version_key(version_str: str) -> tuple:
            """
            Convert a version string into a tuple of integers for proper
            comparison.

            Args:
                version_str (str): Version string (e.g., "5.15.0").

            Returns:
                tuple: Tuple of integers (e.g., (5, 15, 0)).
            """
            return tuple(map(int, version_str.split('.')))

        return sorted(
            releases,
            key=lambda r: version_key(r.get("version") or "0.0.0"),
            reverse=True
        )

    # p u b l i c   m e t h o d s
    #
    # It does not start with an underscore (_), which means it is intended to
    # be part of the public API of the Download class.
    def fetch_latest_versions(self) -> None:
        """
        Fetches the latest stable and longterm (LTS) kernel versions and
        updates the properties.
        """
        data = self._fetch_kernel_data()
        self._stable_version = data.get(
            "latest_stable", {}).get("version")

        longterms = self._filter_longterm_releases(data.get("releases", []))
        longterms_sorted = self._sort_releases_by_version(longterms)
        self._longterm_version = longterms_sorted[0].get(
            "version") if longterms_sorted else None

        logger.trace(
            f"Stable kernel version: {self.stable_version}. "
            f"Longterm kernel version: {self.longterm_version}"
        )


# =====================================================
# CLI Entrypoint
# =====================================================
def main() -> None:

    if sys.platform == "win32":
        colorama.init(autoreset=True)

    parser = argparse.ArgumentParser(
        description="Fetch the latest Linux kernel versions."
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="""Increase output verbosity. Use multiple times for more detail
(e.g., -vvv)."""
    )

    parser.add_argument(
        "--no-verify-ssl",
        action="store_false",
        help="Disable SSL verification (not recommended for production).",
    )

    args = parser.parse_args()

    # --- Initialize Logging --------------------------------------------------
    LogSettings(args.verbose)
    logger.debug(f"Platform: {platform.system()} {platform.release()}")
    logger.debug(f"Python version: {platform.python_version()}")
    logger.debug(f"Executable path: {sys.executable}")

    # --- Assemble Config -----------------------------------------------------
    config = KernelConfig(verbose=args.verbose,)
    logger.debug(f"Loaded config: {config}")

    # --- Execute -------------------------------------------------------------
    kernel_versions = LinuxKernelVersions(config)
    print(f"Latest kernel stable version: {kernel_versions.stable_version}")
    print(
        f"Latest kernel longterm version: {kernel_versions.longterm_version}")


# ====================================
# Script Entry Point
# ====================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Operation cancelled by user.")
        sys.exit(130)
    except Exception as exc:
        logger.exception(f"Unhandled exception: {exc}")
        sys.exit(1)
