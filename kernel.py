#!/usr/bin/env python3

from dataclasses import dataclass
from typing import Final, Optional
import argparse
import platform
import requests
import sys

# =====================================================
# Third-party imports
# =====================================================
from loguru import logger
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
# Data Model
# =====================================================
# slots=True Prevents dynamic attribute assignment, memory-efficient
# frozen=True Makes the instances of the class immutable after creation.
@dataclass(slots=True, frozen=True)
class KernelConfig:
    """

    Attributes:
        os_info (Optional[str]): Detected operating system identifier.
        verbose (int): Verbosity level (0–3).
    """
    verbose: int = 0


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
            timeout (int): Timeout in seconds for HTTP requests.
                           Defaults to DEFAULT_TIMEOUT.
        """
        if sys.platform == "win32":
            colorama.init(autoreset=True)

        self._stable_version: Optional[str] = None
        self._longterm_version: Optional[str] = None

        logger.trace(f"LinuxKernelVersions initialized: {self}")

    # P r o p e r t i e s
    #
    # A property is a special kind of class attribute that lets you control
    # access to an internal variable — typically to encapsulate logic around
    # getting, setting, or deleting its value

    @property
    def longterm_version(self) -> Optional[str]:
        """
        Gets the latest longterm (LTS) kernel version.
        Fetches the latest versions if not already fetched.
        """
        if self._longterm_version is None:
            self._fetch_latest_versions()
        return self._longterm_version

    @longterm_version.setter
    def longterm_version(self, value: str) -> None:
        """
        Sets the latest longterm (LTS) kernel version.
        """
        self._longterm_version = value

    @property
    def stable_version(self) -> Optional[str]:
        """
        Gets the latest stable kernel version.
        Fetches the latest versions if not already fetched.
        """
        if self._stable_version is None:
            self._fetch_latest_versions()
        return self._stable_kernel_version

    @stable_version.setter
    def stable_version(self, value: str) -> None:
        """
        Sets the latest stable kernel version.
        """
        self._stable_version = value


"""
def fetch_latest_versions():
    resp = requests.get(KERNEL_URL, timeout=DEFAULT_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    latest_stable = data.get("latest_stable", {}).get("version")
    # For longterm, there may be multiple entries in `releases` array with moniker "longterm".
    longterms = [r for r in data.get(
        "releases", []) if r.get("moniker") == "longterm"]
    # Sort by version string (simple lexical sort may work if versions all same major)
    longterms_sorted = sorted(
        longterms, key=lambda r: r.get("version") or "", reverse=True)
    latest_longterm = longterms_sorted[0].get(
        "version") if longterms_sorted else None

    return latest_stable, latest_longterm
"""

# =====================================================
# CLI Entrypoint
# =====================================================


def main() -> None:

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="""Increase output verbosity. Use multiple times for more detail
(e.g., -vvv)."""
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
    LinuxKernelVersions(config)


"""
def main():
    try:
        stable, lts = fetch_latest_versions()
        print(f"Latest stable kernel: {stable}")
        print(f"Latest longterm (LTS) kernel: {lts}")
    except Exception as e:
        print("Error fetching kernel versions:", e, file=sys.stderr)
        sys.exit(1)
"""

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
