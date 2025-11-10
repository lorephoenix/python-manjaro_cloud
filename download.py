#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File              : download.py
# Date              : 2025-11-01 13:54:09
# Last Modified time: 2025-11-02 14:11:18
#
# Author:           : Christophe Vermeren <lore.phoenix@gmail.com>
# @License          : MIT License

from __future__ import annotations

"""
Manjaro ISO Downloader
----------------------
A script to download the latest Manjaro Linux ISO for a given architecture and
desktop environment. Supports checksum validation, minimal ISO downloads, and
dry-run mode for testing.

Features:
    - Dynamic URL resolution for the latest ISO
    - Checksum validation (SHA-256, MD5, etc.)
    - Minimal ISO support
    - Dry-run mode for testing
    - Verbose logging and error handling
    - Retry logic for network operations

Usage:
    python download.py --environment xfce --minimal -vv
"""

# =====================================================
# Standard library imports
# =====================================================
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Optional
import argparse
import hashlib
import platform
import re
import sys

# =====================================================
# Third-party imports
# =====================================================
from loguru import logger  # Modern, flexible logging
from tenacity import retry, RetryError, stop_after_attempt, wait_exponential
from tqdm import tqdm  # Progress bar for downloads
import certifi  # SSL certificates for secure requests
import colorama  # Cross-platform colored terminal text
import requests  # HTTP requests


# =====================================================
# Constants
# =====================================================
DEFAULT_TIMEOUT: Final[int] = 5
LOG_BUFFER: deque[str] = deque(maxlen=1000)  # Buffer for log messages
MANJARO_URL: Final[str] = "https://manjaro.org/products/download/x86"


# =====================================================
# Custom Exceptions
# =====================================================
class DownloadError(Exception):
    """Base class for download-related errors."""


class UnsupportedArchitectureError(DownloadError):
    """Raised when the architecture is not supported."""


class NetworkError(DownloadError):
    """Raised when a network operation fails."""


class ChecksumError(DownloadError):
    """Raised when checksum validation fails."""


# =====================================================
# Custom Help Formatter
# =====================================================
class SelectiveBlankLineFormatter(argparse.ArgumentDefaultsHelpFormatter):
    """
    Custom HelpFormatter that adds a blank line before certain arguments
    for improved readability in CLI help output.
    """

    def add_argument(self, action):
        # Only inject a blank line before the "--digest" argument
        if (
            hasattr(action, "option_strings")
            and "--digest" in action.option_strings
        ):
            # Add a blank line before `--digest`
            self._add_item(lambda: "\n", [])
        # Always call super() after modifying layout
        super().add_argument(action)


# =====================================================
# Logging Helpers
# =====================================================
class LogBufferHandler:
    """
    Custom log handler to buffer log messages for later output.
    Useful for debugging or logging in environments where real-time output is
    not desired.
    """

    def __init__(self) -> None:
        self.buffer: deque[str] = LOG_BUFFER

    def __call__(self, message: str) -> None:
        """Append log message to buffer."""
        self.buffer.append(message)


# =====================================================
# Data Model
# =====================================================
# slots=True Prevents dynamic attribute assignment, memory-efficient
# frozen=True Makes the instances of the class immutable after creation.
@dataclass(slots=True, frozen=True)
class DownloadConfig:
    """
    Configuration options for the Manjaro ISO download process.

    Attributes:
        environment (str): Desktop environment (e.g., kde, xfce, gnome).
        digest (str): Checksum algorithm (e.g., sha256).
        dry_run (bool): Simulate the download process.
        force (bool): Force download even if the file exists.
        minimal (bool): Download the minimal ISO image.
        skip_digest (bool): Skip checksum validation.
        target_dir (Path): Directory to save the downloaded files.
        verify_ssl (bool): Verify SSL certificates.
        verbose (int): Verbosity level.
    """
    environment: str = "kde"
    digest: str = "sha256"
    dry_run: bool = False
    force: bool = False
    minimal: bool = False
    skip_digest: bool = False
    target_dir: Path = field(default_factory=Path.cwd)
    verify_ssl: bool = True
    verbose: int = 0


# =====================================================
# Core Download Class
# =====================================================
class Download:
    """
    Handles Manjaro ISO download logic.

    Attributes:
        config (DownloadConfig): Configuration for the download process.
        session (requests.Session): HTTP session for downloads.
        _iso_url (Optional[str]): Latest ISO URL.
        _iso_image (Optional[str]): Name of the ISO file.
        _iso_version (Optional[str]): Version of the ISO.
        _checksum_url (Optional[str]): URL of the checksum file.
        _checksum_file (Optional[str]): Name of the checksum file.
    """

    # d u n d e r   m e t h o d s
    #
    # Methods with double underscores (e.g., __str__, __init__, __repr__) are
    # called "dunder" methods (short for "double underscore"). These are
    # special methods that Python uses for specific operations, such as string
    # representation, object initialization, etc. They are part of Python's
    # data model and are always public.

    def __init__(self, config: DownloadConfig) -> None:
        """
        Initialize the Download class with configuration and session setup.
        """
        if sys.platform == "win32":
            colorama.init(autoreset=True)

        self.config = config
        self.session = requests.Session()
        self.session.verify = certifi.where() if config.verify_ssl else False
        self.session.headers.update(
            {"User-Agent": "ManjaroISO-Downloader/1.0"})
        self._iso_image: Optional[str] = None
        self._iso_version: Optional[str] = None
        self._checksum_url: Optional[str] = None
        self._checksum_file: Optional[str] = None

        logger.trace(f"Download initialized: {self}")

        # =====================================================
        # Directory Checks
        # =====================================================
        self._check_dir()

        # =====================================================
        # Network Checks
        # =====================================================
        # The @retry decorator below automatically retries failed network calls
        try:
            self._check_url()
        except RetryError as err:
            raise NetworkError(f"Failed to reach URL: {MANJARO_URL} - {err}")

        # =====================================================
        # Metadata Extraction
        # =====================================================
        self._resolve_iso_url()
        self._resolve_checksum_url()
        self._extract_metadata()
        logger.trace(self)

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
    def iso_image(self) -> Optional[str]:
        """Get the ISO image filename."""
        return self._iso_image

    @iso_image.setter
    def iso_image(self, value: Optional[str]) -> None:
        """Set the ISO image filename."""
        self._iso_image = value

    @property
    def iso_version(self) -> Optional[str]:
        """Get the ISO version."""
        return self._iso_version

    @iso_version.setter
    def iso_version(self, value: Optional[str]) -> None:
        """Set the ISO version."""
        self._iso_version = value

    # p r o t e c t e d   m e t h o d s
    #
    # The underscore (_) signals to other developers that this method is
    # intended for internal use within the class or its subclasses. It is not
    # meant to be accessed directly from outside the class.

    def _check_dir(self) -> None:
        """Check if the target directory exists."""
        if not self.config.target_dir.is_dir():
            raise DownloadError(
                f"Directory does not exist: {self.config.target_dir}"
            )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10))
    def _check_url(self) -> None:
        """Check if the configured URL is reachable."""

        try:
            response = self.session.head(
                MANJARO_URL,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            raise NetworkError(f"Failed to reach URL: {err}")
        else:
            logger.success(f"The URL is reachable: {MANJARO_URL}")

    def _resolve_checksum_url(self) -> None:
        """Construct and validate the checksum URL."""
        if self.config.skip_digest:
            logger.warning("Skipping checksum validation per user request.")
            return

        self._checksum_url = f"{self._iso_url}.{self.config.digest}"

        try:
            response = self.session.head(
                self._checksum_url,
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=True
            )
            response.raise_for_status()
            logger.success(f"Checksum file located: {self._checksum_url}")
        except requests.exceptions.RequestException as err:
            raise NetworkError(f"Checksum URL unreachable: {err}") from err

    def _resolve_iso_url(self) -> None:
        """Find the latest Manjaro ISO link matching the environment filter."""
        try:
            response = self.session.get(MANJARO_URL, timeout=DEFAULT_TIMEOUT)
            logger.trace(f"Response status code: {response.status_code}")
            response.raise_for_status()

            iso_links = re.findall(r'href="(.*?)"', response.text)
            pattern = (rf".*/([Mm]anjaro-.*{self.config.environment}-.*.iso)$")
            filtered = [link for link in iso_links if re.search(pattern, link)]

            logger.trace(f"iso_links: {iso_links}")
            logger.debug(f"pattern: {pattern}")
            logger.debug(f"filtered: {filtered}")

            if not filtered:
                raise DownloadError(
                    f"No ISO found for environment: {self.config.environment}"
                )
            self._iso_url = sorted(filtered, reverse=True)[0]
            if self.config.minimal:
                self._iso_url = re.sub(
                    r'(manjaro-[^-]+-\d+\.\d+\.\d+)-',
                    r'\1-minimal-',
                    self._iso_url,
                    count=1
                )
            logger.success(f"Resolved ISO URL: {self._iso_url}")
        except requests.exceptions.RequestException as err:
            raise NetworkError(f"Failed to fetch ISO list: {err}")

    def _extract_metadata(self) -> None:
        """Extract ISO filename and version from the URL."""
        self._iso_image = self._iso_url.split("/")[-1]
        self._iso_version = re.search(
            r"(([0-9]+\.[0-9]+\.[0-9]+)|([0-9]+\.[0-9]+)|([0-9]+T))",
            self._iso_image
        ).group(0)
        if not self.config.skip_digest:
            self._checksum_file = self._checksum_url.split("/")[-1]
        logger.debug(
            f"Class instance attribute '_iso_version': {self._iso_version}")
        logger.debug(
            f"Class instance attribute '_iso_image': {self._iso_image}")
        logger.debug(
            f"Class instance attribute '_checksum_file': "
            f"{self._checksum_file}")

    def _download_file(self, url: str, description: str) -> None:
        """
        Download a remote file with progress bar.

        Args:
            url (str): URL of the file to download.
            description (str): Description of the file (e.g., "ISO").
        """
        file_name = url.split("/")[-1]
        file_path = self.config.target_dir / file_name

        if file_path.exists() and not self.config.force:
            logger.debug(f"File {file_name} already exists.")
            return

        try:
            with self.session.get(
                url,
                stream=True,
                timeout=DEFAULT_TIMEOUT
            ) as response:
                response.raise_for_status()
                with file_path.open("wb") as f:
                    for chunk in tqdm(
                        response.iter_content(chunk_size=1024),
                        unit="KB",
                        unit_scale=True,
                        desc=f"Downloading {file_name}",
                    ):
                        f.write(chunk)
            logger.success(
                f"Downloaded '{file_name}' to {self.config.target_dir}")
        except requests.exceptions.RequestException as err:
            raise NetworkError(
                f"Failed to download {description}: {err}") from err

    # p u b l i c   m e t h o d s
    #
    # It does not start with an underscore (_), which means it is intended to
    # be part of the public API of the Download class.

    def download(self) -> None:
        """Download ISO and (optionally) checksum files."""
        if self.config.dry_run:
            logger.info("[DRY RUN] Would download ISO and checksum files.")
            return

        self._download_file(self._iso_url, "ISO")
        if not self.config.skip_digest:
            self._download_file(self._checksum_url, "checksum")

    def validate_checksum(self) -> bool:
        """
        Verify downloaded ISO against its official checksum.

        Returns:
            bool: True if checksum is valid, False otherwise.
        """
        if self.config.skip_digest:
            logger.warning(
                "Checksum validation skipped by user configuration.")
            return True

        if self.config.dry_run:
            logger.info("[DRY RUN] Would verify checksum.")
            return True

        algo = getattr(hashlib, self.config.digest, None)
        if not algo:
            raise ChecksumError(
                f"Unsupported checksum algorithm: {self.config.digest}"
            )

        iso_path = self.config.target_dir / self._iso_image
        checksum_path = self.config.target_dir / self._checksum_file

        # Compute file hash
        hash_obj = algo()
        with iso_path.open("rb") as iso_file:
            for chunk in iter(lambda: iso_file.read(1024), b""):
                hash_obj.update(chunk)
        computed_hash = hash_obj.hexdigest()

        # Compare to expected
        with checksum_path.open("r", encoding="utf-8") as f:
            expected_hash = f.read().split()[0]

        if computed_hash == expected_hash:
            logger.success("Checksum verified successfully.")
            return True
        else:
            raise ChecksumError("Checksum verification failed.")


# =====================================================
# Logging Configuration
# =====================================================
def configure_logging(verbosity: int) -> None:
    """
    Configure loguru logging levels dynamically based on verbosity.
    """
    log_levels = {0: "WARNING", 1: "INFO", 2: "DEBUG", 3: "TRACE"}
    level = log_levels.get(verbosity, "TRACE")

    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{file}{function}</cyan> - "
        "<level>{message}</level>"
    )

    logger.remove()
    logger.add(sys.stderr, level=level, format=log_format)

    # Optionally store logs in memory for later use (only when verbosity > 3)
    if verbosity > 3:
        logger.add(LogBufferHandler(), level="TRACE", format=log_format)


# =====================================================
# CLI Entrypoint
# =====================================================
def main() -> None:
    """Main function to parse arguments and initiate download."""
    parser = argparse.ArgumentParser(
        formatter_class=SelectiveBlankLineFormatter,
        description="Download the latest Manjaro ISO.",
    )

    # --- Arguments -----------------------------------------------------------
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force download even if the file exists."
    )

    parser.add_argument(
        "-m",
        "--minimal",
        action="store_true",
        help="Download the minimal ISO image (smaller size, fewer packages)."
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
        "--digest",
        type=str,
        default="sha256",
        help="""A cryptographic hash value (e.g., MD5, SHA-1, or SHA-256) used
to verify the integrity and authenticity of a fileSpecify a checksum hash
value."""
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the download process.",
    )

    parser.add_argument(
        "--environment",
        type=str,
        default="kde",
        help="Desktop environment (e.g., xfce, kde, gnome)."
    )

    parser.add_argument(
        "--no-verify-ssl",
        action="store_false",
        help="Disable SSL verification (not recommended for production).",
    )

    parser.add_argument(
        "--skip-digest",
        action="store_true",
        help="Skip checksum validation."
    )

    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path.cwd(),
        help="Store download image into DIRECTORY."
    )

    args = parser.parse_args()

    # --- Initialize Logging --------------------------------------------------
    configure_logging(args.verbose)
    logger.debug(f"Platform: {platform.system()} {platform.release()}")
    logger.debug(f"Python version: {platform.python_version()}")
    logger.debug(f"Executable path: {sys.executable}")

    # --- Assemble Config -----------------------------------------------------
    config = DownloadConfig(
        environment=args.environment,
        dry_run=args.dry_run,
        digest=args.digest,
        force=args.force,
        minimal=args.minimal,
        skip_digest=args.skip_digest,
        target_dir=args.target_dir,
        verbose=args.verbose,
        verify_ssl=args.no_verify_ssl,
    )

    # --- Execute -------------------------------------------------------------
    try:
        downloader = Download(config)
        downloader.download()
        downloader.validate_checksum()
    except DownloadError as e:
        logger.error(f"Download failed: {e}")
        sys.exit(1)


# ====================================
# Script Entry Point
# ====================================
if __name__ == "__main__":
    main()
