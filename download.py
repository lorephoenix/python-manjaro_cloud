#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# File              : download.py
# Date              : 2025-11-01 13:54:09
# Last Modified time: 2025-11-02 14:11:18
#
# Author:           : Christophe Vermeren <lore.phoenix@gmail.com>
# @License          : MIT License

"""
Manjaro ISO Downloader
----------------------
This script automates the process of downloading the latest Manjaro Linux ISO
for your system architecture (x86_64).

Features:
    - Detects system architecture
    - Fetches latest ISO link dynamically
    - Verifies download directory and URL reachability
    - Supports checksum verification and minimal images
    - Provides configurable logging verbosity

Usage:
    python download.py --environment xfce --machine arm64 --verbose
"""

# =====================================================
# Standard library imports
# =====================================================
from collections import deque
from pathlib import Path
from typing import (
    Any,
    Dict,
    Final,
    List,
    Optional,
    Pattern,
    Match,
)
import argparse
import hashlib
import os
import platform
import random
import re
import sys

# =====================================================
# Third-party imports
# =====================================================
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential
from tqdm import tqdm
import certifi
import colorama
import requests

# =====================================================
# Constants
# =====================================================
LOG_BUFFER: deque[str] = deque(maxlen=1000)  # Buffer for log messages
MANJARO_URL: Final[str] = "https://manjaro.org/products/download/x86"


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
            # Must pass a lambda that takes *no* arguments
            self._add_item(lambda: "\n", [])
        # Always call super() after modifying layout
        super().add_argument(action)


# =====================================================
# Logging Helpers
# =====================================================
class LogBufferHandler:
    """Custom log handler to buffer log messages for later output."""

    def __init__(self) -> None:
        self.buffer: deque[str] = LOG_BUFFER

    def __call__(self, message: str) -> None:
        """Append log message to buffer."""
        self.buffer.append(message)


# =====================================================
# Core Download Class
# =====================================================
class Download:
    """
    Class to handle Manjaro ISO download logic based on machine architecture
    and environment.

    Features:
        - Validates URLs
        - Fetches latest ISO link dynamically
        - Supports checksum and minimal images
        - Supports dry-run mode for testing.

    Attributes:
        environment (str): Desktop environment (default: "xfce").
        force (bool): Force download even if the file exists.
        dry_run (bool): Simulate the download process without making changes.
        minimal (bool): Download minimal image.
        selected_machine (str): Machine architecture
                                (default: platform.machine()).
        target_dir (str): Target directory (default: current directory).
        url (Optional[str]): Configured download URL.
        iso_url (str): Latest ISO URL.
        iso_image (str): Extracted ISO image filename.
        iso_version (str): Extracted ISO version.
        verbose (int): Verbosity level (default: 0).
    """

    def __init__(self, **kwargs: Dict[str, Any]) -> None:
        """
        Initialize the Download object.

        Args:
            **kwargs (Dict[str, Any]):
                - dry_run (bool): Simulate the download process
                                  (default: False).
                - environment (str): Desktop environment
                                     (default: "xfce").
                - force (bool): Force download even if file exists
                                (default: False).
                - minimal (bool): Download minimal image
                                  (default: False).
                - no_verify_ssl (bool): Disable SSL verification
                                        (default: False).
                - selected_machine (str): Machine architecture
                                          (default: platform.machine()).
                - target_dir (str): Target directory
                                    (default: current directory)
                - verbose (int): Verbosity level
                                 (default: 0).

        Raises:
            SystemExit: If initialization fails due to invalid arguments or
                        unsupported architecture.
        """

        # -----------------------
        # Initialization
        # -----------------------
        self.auto: bool = kwargs.get("auto", False)
        self.digest: str = kwargs.get("digest", "sha256")
        self.dry_run: bool = kwargs.get("dry_run", False)
        self.environment: str = kwargs.get("environment", "kde")
        self.force: bool = kwargs.get("force", False)
        self.minimal: bool = kwargs.get("minimal", False)
        self.no_verify_ssl: bool = kwargs.get("no_verify_ssl", False)
        self.selected_machine: str = kwargs.get(
            "selected_machine",
            platform.machine()
        )
        self.target_dir: str = kwargs.get("target_dir", os.getcwd())
        self.verbose: int = kwargs.get("verbose", 0)
        self.verify: bool = (
            self.no_verify_ssl if self.no_verify_ssl else certifi.where()
        )

        # -----------------------
        # Internal state
        # -----------------------
        self.url: Optional[str] = None
        self._iso_image: Optional[str] = None
        self._iso_url: Optional[str] = None
        self._iso_version: Optional[str] = None
        self._checksum_file: Optional[str] = None
        self._checksum_url: Optional[str] = None

        # Initialize colorama for Windows
        if sys.platform == "win32":
            colorama.init()

        # Log system info if verbosity >= 2
        if self.verbose >= 2:
            logger.debug(f"Platform: {platform.system()} {platform.release()}")
            logger.debug(f"Python version: {platform.python_version()}")
            logger.debug(f"Executable path: {sys.executable}")

            if self.verify:
                logger.debug(f"--no_verfy_ssl: enabled")

        # -----------------------
        # Execution Flow
        # -----------------------
        self._configure_url()
        self._check_dir()
        self._check_url()
        latest_url: str = self._get_latest_iso_url()

        # 💡 Fetch and verify both ISO and checksum URLs
        self.iso_url: str = self._check_url_file(latest_url, "ISO")
        self.checksum_url: str = self._check_url_file(
            f"{self.iso_url}.{self.digest}",
            "checksum"
        )

        # Extract metadata
        self.checksum_file: str = self._get_checksum_file()
        self.iso_image: str = self._get_iso_image()
        self.iso_version = self._get_iso_version()

        if self.auto:
            # Cleanup & Download
            self.remove_checksum()
            self.remove_image()
            self.download_checksum()
            self.download_image()

            # Validate
            if not self.validate_checksum():
                logger.error("Downloaded ISO failed checksum validation!")
                sys.exit(1)

    # Ｐｒｏｔｅｃｔｅｄ  ｍｅｔｈｏｄｓ

    # =====================================================
    # Directory Checks
    # =====================================================
    def _check_dir(self) -> None:
        """
        Check if the target directory exists. If not, log an error and exit.

        Raises:
            SystemExit: If the directory does not exist or is invalid.
        """
        # Ensure target_dir is a non-empty string
        if not isinstance(self.target_dir, str) or not self.target_dir.strip():
            logger.error("Target directory must be a non-empty string.")
            sys.exit(1)

        # Normalize and validate
        target_path = os.path.abspath(os.path.expanduser(self.target_dir))
        if not os.path.isdir(target_path):
            logger.error(f"The directory '{target_path}' does not exist.")
            sys.exit(1)

        self.target_dir = target_path
        logger.debug(f"Target directory verified: {target_path}")

    # =====================================================
    # Network Checks
    # =====================================================
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(
            multiplier=1,
            min=4,
            max=10
        )
    )
    def _check_url(self, timeout: int = 5) -> bool:
        """
        Check if the configured URL is reachable.

        Args:
            timeout (int): Timeout in seconds for the request (default: 5).

        Returns:
            bool: True if URL is reachable, False otherwise.

        Raises:
            SystemExit: If URL is unreachable.
        """
        try:
            response = requests.head(
                self.url,
                timeout=timeout,
                allow_redirects=True,
                verify=self.verify
            )

            if response.status_code >= 400 or response.status_code < 100:
                response = requests.get(
                    self.url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=self.verify
                )

            logger.success(f"The URL is reachable: {self.url}")
            return True
        except requests.exceptions.RequestException as err:
            logger.debug(f"Error occurred while reaching {self.url}: {err}")
            sys.exit(1)

    def _check_url_file(self, url: str, description: str, timeout: int = 5):
        """
        Check if a file exists at the given URL.

        Args:
            url (str): URL of the file.
            description (str): Description for logging purposes
                               (e.g., "ISO", "Checksum").
            timeout (int): Timeout in seconds for the request (default: 5).

        Returns:
            Optional[str]: The URL of the file if found

        Raises:
            SystemExit: If the file is not found or an error occurs.
        """
        if not url:
            logger.warning(
                f"No {url} url provided; skipping removal.")
            return

        try:
            # Send a HEAD request to check if the checksum file exists
            response = requests.head(
                url,
                allow_redirects=True,
                timeout=timeout,
                verify=self.verify
            )

            # Some servers may not allow HEAD requests → fallback to GET
            if response.status_code >= 400 or response.status_code < 100:
                logger.debug("HEAD request failed; falling back to GET.")
                response = requests.get(
                    url,
                    stream=True,
                    timeout=timeout,
                    verify=self.verify
                )

            # Check if the server confirms the file's presence (2xx or
            # 3xx status)
            if 200 <= response.status_code < 400:
                logger.success(f"{description} file found remotely: {url}")
                return url

            # If the file is not found (404) or another error occur
            logger.error(f"{description} file not found at: {url}")
            sys.exit(1)

        except requests.exceptions.RequestException as err:
            logger.error(
                f"Error checking {description} URL '{url}': {err}")
            sys.exit(1)

    # =====================================================
    # Architecture & URL Configuration
    # =====================================================
    def _configure_url(self) -> None:
        """
        Configure the download URL based on machine architecture.

        Raises:
            SystemExit: If the architecture is unsupported.
        """
        if self._is_x86():
            self.url = f"{MANJARO_URL}"
        else:
            logger.error(
                f"Unsupported architecture: '{self.selected_machine}'. "
                "Manjaro only supports x86_64 or ARM (aarch64/arm64)."
            )
            sys.exit(1)
        logger.debug(f"Configured download URL: {self.url}")

    def _is_x86(self) -> bool:
        """
        Check if the selected machine is x86-based.

        Returns:
            bool: True if the machine is AMD64/x86_64, False otherwise.
        """
        return self.selected_machine.lower() in ("amd64", "x86_64")

    # =====================================================
    # File Downloads
    # =====================================================
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        reraise=True
    )
    def _download_file(self, url: str, description: str) -> None:
        """
        Download a file from the URL to the target directory.

        Args:
            url (str): URL of the file.
            description (str): Description for logging purposes
                               (e.g., "ISO", "checksum").
        """
        if not url:
            logger.warning(
                f"No {url} url provided; skipping removal.")
            return

        file_name: str = url.split("/")[-1]
        file_path: Path = Path(self.target_dir) / file_name

        if Path.exists(file_path):
            logger.debug(f"File {file_name} already exist.")
            return

        if self.dry_run:
            logger.info(
                f"[DRY RUN] Would download {description} file: {file_name}"
            )
            return

        try:
            response = requests.get(
                url,
                stream=True,
                verify=self.verify
            )
            response.raise_for_status()
            with file_path.open("wb") as handle:
                for data in tqdm(
                    response.iter_content(chunk_size=1024),
                    unit="KB",
                    unit_scale=True,
                    desc=f"Downloading {file_name}",
                ):
                    handle.write(data)
            logger.success(
                f"File '{file_name}' downloaded to {self.target_dir}.")
        except requests.exceptions.RequestException as err:
            logger.error(f"Failed to download {description}: {err}")
            sys.exit(1)

    # =====================================================
    # Metadata Extraction
    # =====================================================
    def _get_latest_iso_url(self) -> str:
        """
        Fetch the latest ISO URL from the Manjaro download page.

        Returns:
            str: The latest ISO URL.

        Raises:
            SystemExit: If no ISO URL is found or request fails.
        """
        url_pattern: str = 'href="(.*?)"'
        filter_value: Pattern = re.compile(
            rf".*/([Mm]anjaro-.*{self.environment}-.*(.iso|.img.xz))$"
        )

        # Randomize User-Agent to avoid blocking
        user_agents: List = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Opera/9.25 (Windows NT 5.1; U; en)",
            "Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.2.9",
        ]
        headers: Dict[str, str] = {"User-Agent": random.choice(user_agents)}

        try:
            response = requests.get(
                self.url,
                headers=headers,
                verify=self.verify
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            logger.error(f"Failed to fetch ISO list: {err}")
            sys.exit(1)

        # Extract and filter ISO URLs
        iso_links: List[str] = re.findall(url_pattern, response.text)
        filtered: List[str] = list(filter(filter_value.match, iso_links))

        if not filtered:
            logger.error(f"No ISO found for environment: {self.environment}")
            sys.exit(1)

        # Return the latest ISO (sorted in reverse order)
        filtered .sort(reverse=True)
        latest_iso = sorted(filtered, reverse=True)[0]

        if self.minimal:
            pattern: str = r'(manjaro-[^-]+-\d+\.\d+\.\d+)-'
            replacement: str = r'\1-minimal-'
            latest_iso: str = re.sub(
                pattern,
                replacement,
                latest_iso,
                count=1
            )

        logger.debug(f"Latest ISO URL resolved: {latest_iso}")
        return latest_iso

    def _get_checksum_file(self) -> str:
        """Extract the checksum filename from the checksum URL."""
        filename: str = self.checksum_url.split("/")[-1]
        logger.info(f"Checksum file: {filename}")
        return filename

    def _get_iso_image(self) -> str:
        """Extract the ISO image filename from the ISO URL."""
        if not self.iso_url:
            logger.warning(
                f"No {self.iso_url} url provided; skipping removal.")
            return

        iso_image: str = self.iso_url.split("/")[-1]
        logger.info(f"CD/DVD ISO image: {iso_image}")

        return iso_image

    def _get_iso_version(self) -> str:
        """
        Extract the version number from the ISO URL.

        Returns:
            str: The version number of the ISO.

        Raises:
            SystemExit: If version cannot be extracted.
        """
        if not self.iso_image:
            logger.warning(
                f"No {self.iso_url} image provided; skipping removal.")
            return

        match: Optional[Match[str]] = re.search(
            r"(([0-9]+\.[0-9]+\.[0-9]+)|([0-9]+\.[0-9]+)|([0-9]+T))",
            self.iso_image,
        )
        if not match:
            logger.error(f"Could not extract version from: {self.iso_image}")
            sys.exit(1)
        version: str = match.group(0)
        logger.info(f"Manjaro Linux version: {version}")
        return version

    # =====================================================
    # File Cleanup
    # =====================================================
    def _remove_file(self, file_name: str, description: str) -> None:
        """
        Remove a file in the target directory if it exists and force mode is
        enabled.

        Args:
            file_name (str): Name of the file to remove.
            description (str): Description for logging purposes
                               (e.g., "ISO", "checksum").
        """
        if not file_name:
            logger.warning(
                f"No {description} file name provided; skipping removal.")
            return

        file_path = Path(self.target_dir) / file_name
        if not file_path.is_file():
            logger.debug(
                f"No existing {description} file to remove: {file_path}")
            return

        if not self.force:
            message = f"Force mode disabled; keeping existing {description} "
            message += f"file: {file_path}"
            logger.info(message)
            return

        try:
            file_path.unlink()
            logger.debug(f"Removed existing {description} file: {file_path}")
        except (PermissionError, OSError) as e:
            logger.error(
                f"Failed to remove {description} file '{file_path}': {e}")
            sys.exit(1)

    # pｕｂｌｉｃ  ｍｅｔｈｏｄｓ

    # =====================================================
    # File Downloads
    # =====================================================
    def download_checksum(self) -> None:
        """Download the checksum file."""
        logger.trace("Using protected method: _download_file")
        self._download_file(self.checksum_url, "checksum")

    def download_image(self) -> None:
        """Download the ISO file."""
        logger.trace("Using protected method: _download_file")
        self._download_file(self.iso_url, "ISO")

    # =====================================================
    # File Cleanup
    # =====================================================
    def remove_image(self) -> None:
        """Remove the ISO file if it exists and force mode is enabled."""
        self._remove_file(self.iso_image, "ISO")

    def remove_checksum(self) -> None:
        """Remove the checksum file if it exists and force mode is enabled."""
        self._remove_file(self.checksum_file, "checksum")

    # =====================================================
    # Validate
    # =====================================================
    def validate_checksum(self) -> bool:
        """
        Validate the downloaded ISO file against its checksum.

        Returns:
            bool: True if checksum matches, False otherwise.
        """
        algo = getattr(hashlib, self.digest, None)
        if not algo:
            logger.error(f"Unsupported checksum algorithm: {self.digest}")
            return False

        iso_path = Path(self.target_dir) / self.iso_image
        checksum_path = Path(self.target_dir) / self.checksum_file

        if self.dry_run:
            logger.info(
                f"[DRY RUN] Would verify checksum."
            )
            return True

        # Compute hash incrementally (efficient for large ISOs)
        hash_obj = algo()
        with open(iso_path, "rb") as iso_file:
            for chunk in iter(lambda: iso_file.read(1024), b""):
                hash_obj.update(chunk)
        iso_hash = hash_obj.hexdigest()

        # Read expected checksum (usually first token in checksum file)
        with open(checksum_path, "r", encoding="utf-8") as f:
            expected_hash = f.read().split()[0]

        if iso_hash == expected_hash:
            logger.success("Checksum verified successfully.")
            return True
        else:
            logger.error("Checksum verification failed.")
            logger.debug(f"Expected: {expected_hash}")
            logger.debug(f"Got:      {iso_hash}")
            return False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def checksum_file(self) -> Optional[str]:
        """Get the checksum filename."""
        return self._checksum_file

    @checksum_file.setter
    def checksum_file(self, value: Optional[str]) -> None:
        """Set the checksum filename."""
        self._checksum_file = value

    @property
    def checksum_url(self) -> Optional[str]:
        """Get the checksum URL."""
        return self._checksum_url

    @checksum_url.setter
    def checksum_url(self, value: Optional[str]) -> None:
        """Set the checksum URL."""
        if value and not value.startswith("http"):
            raise ValueError("URL must start with 'http'")
        self._checksum_url = value

    @property
    def iso_image(self) -> Optional[str]:
        """Get the ISO image filename."""
        return self._iso_image

    @iso_image.setter
    def iso_image(self, value: Optional[str]) -> None:
        """Set the ISO image filename."""
        self._iso_image = value

    @property
    def iso_url(self) -> Optional[str]:
        """Get the ISO URL."""
        return self._iso_url

    @iso_url.setter
    def iso_url(self, value: Optional[str]) -> None:
        if value and not value.startswith("http"):
            raise ValueError("URL must start with 'http'")
        self._iso_url = value

    @property
    def iso_version(self) -> Optional[str]:
        """Get the ISO version."""
        return self._iso_version

    @iso_version.setter
    def iso_version(self, value: Optional[str]) -> None:
        """Set the ISO version."""
        self._iso_version = value


# =====================================================
# Logging Configuration
# =====================================================
def configure_logging(verbosity: int) -> None:
    """
    Configure logging level based on verbosity.
    If verbosity > 3, buffer all logs and print them at the end.

    Args:
        verbosity (int): Verbosity level (0-3+).
    """
    log_levels = {
        0: "WARNING",
        1: "INFO",
        2: "DEBUG",
        3: "TRACE",
    }
    level: str = log_levels.get(verbosity, "TRACE")

    # Define log format (PEP 8-compliant line breaks)
    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{function}</cyan> - "
        "<level>{message}</level>"
    )

    logger.remove()
    logger.add(sys.stderr, level=level, format=log_format)
    if verbosity > 3:
        log_buffer_handler = LogBufferHandler()
        logger.add(log_buffer_handler, level="TRACE", format=log_format)


def print_buffered_logs() -> None:
    """Print all buffered log messages."""
    print("\n--- Buffered Logs ---")
    for log in LOG_BUFFER:
        print(log)
    print("--- End of Buffered Logs ---\n")


# =====================================================
# Entry Point
# =====================================================
def main() -> None:
    """
    Main function to parse arguments, configure logging, and initiate download.
    """

    # Retrieve the machine architecture (e.g., 'x86_64', 'arm64')
    machine_arch = platform.machine()

    parser = argparse.ArgumentParser(
        formatter_class=SelectiveBlankLineFormatter,
        description="""Download the latest Manjaro ISO for your architecture.
\nSupported environments: xfce, kde, gnome.
\nSupported architectures: Only x86_64.""",
    )

    parser.add_argument(
        "-a",
        "--auto",
        action="store_true",
        default=True,
        help=f"Specify a Desktop Environment."
    )

    parser.add_argument(
        "-e",
        "--environment",
        type=str,
        default="kde",
        help=f"Specify a Desktop Environment."
    )

    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Ignore existent download image."
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
        help="Simulate the download process without making changes.",
    )

    parser.add_argument(
        "--minimal",
        action="store_true",
        help="Download the minimal ISO image (smaller size, fewer packages)."
    )

    parser.add_argument(
        "--no_verify_ssl",
        action="store_true",
        help="Disable SSL verification (not recommended for production).",
    )

    parser.add_argument(
        "--target_dir",
        type=str,
        default=os.getcwd(),
        help="Store download image into DIRECTORY."
    )

    # Parse and Process Arguments
    args = parser.parse_args()
    configure_logging(args.verbose)

    # ----------------------------
    # Core Logic
    # ----------------------------
    if args.verbose >= 3:
        current_file = os.path.abspath(__file__)
        logger.trace(f"Current script file: {current_file}")

    # Initialize Download
    Download(
        **{
            "verbose": args.verbose,
            "auto": args.auto,
            "digest": args.digest,
            "dry_run": args.dry_run,
            "environment": args.environment,
            "force": args.force,
            "minimal": args.minimal,
            "no-verify-ssl": args.no_verify_ssl,
            "selected_machine": machine_arch,
            "target_dir": args.target_dir
        })


# ====================================
# Script Entry Point
# ====================================
if __name__ == "__main__":
    main()
