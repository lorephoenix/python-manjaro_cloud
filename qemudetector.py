#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# File              : qemudetector.py
# Date              : 2025-11-08 09:55:21
# Last Modified time: 2025-11-08 16:14:47
#
# Author:           : Christophe Vermeren <lore.phoenix@gmail.com>
# @License          : MIT License

from __future__ import annotations

# =====================================================
# Standard library imports
# =====================================================
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import argparse
import platform
import shutil
import subprocess
import sys

# =====================================================
# Third-party imports
# =====================================================
from loguru import logger
import colorama


# =====================================================
# Constants
# =====================================================
LOG_BUFFER: deque[str] = deque(maxlen=1000)  # Buffer for log messages


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
# Prevents dynamic attribute assignment, memory-efficient
@dataclass(slots=True)
class QemuConfig:
    """
    Configuration options for QEMU detection and verification.

    Attributes:
        os_info (Optional[str]): Detected operating system identifier.
        verbose (int): Verbosity level (0–3).
    """
    os_info: Optional[str] = None
    verbose: int = 0


class QemuDetector:
    """
    A class to detect the operating system and provide QEMU package installation
    details.
    """

    # d u n d e r   me t h o d s
    #
    # Methods with double underscores (e.g., __str__, __init__, __repr__) are
    # called "dunder" methods (short for "double underscore"). These are
    # special methods that Python uses for specific operations, such as string
    # representation, object initialization, etc. They are part of Python's
    # data model and are always public.

    def __init__(self, config: PackageConfig) -> None:
        """
        Initialize the QemuDetector and detect the OS.

        Args:
            config (QemuConfig): Configuration object.
        """
        self.config = config
        self.config.os_info: str = self._detect_os()
        self.commands: Dict[str, Dict[str, str]] = self._get_commands()

        logger.info(f"Detected OS: {self.config.os_info}")
        logger.trace(self)
        self.check_commands()

    def __str__(self):
        ''' This method returns the string representation of the object.
            This method is called when print() or str() function is invoked on
            an object.
        '''
        return str(self.__class__) + ": " + str(self.__dict__)

    # p r o t e c t e d   me t h o d s
    #
    # The underscore (_) signals to other developers that this method is
    # intended for internal use within the class or its subclasses. It is not
    # meant to be accessed directly from outside the class.

    # --------------------------------------------------
    # Command Checking
    # --------------------------------------------------
    def _check_command(self, command: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a command exists in the user's PATH.

        Args:
            command (str): Command to verify.

        Returns:
            Tuple[bool, Optional[str]]: (exists, absolute_path)
        """
        path: Optional[str] = shutil.which(command)
        return (path is not None, path)

    # --------------------------------------------------
    # OS Detection
    # --------------------------------------------------
    def _detect_os(self) -> str:
        """
        Detect the host operating system.

        Returns:
            str: The detected OS identifier (e.g., 'windows', 'ubuntu', 'debian').

        Notes:
            - Uses `platform.system()` for base OS.
            - On Linux, reads `/etc/os-release` for distro ID or ID_LIKE.
        """
        system: str = platform.system().lower()

        if system == "windows":
            return "windows"

        if system == "linux":
            os_release: Dict[str, str] = self._get_os_release()
            distro: str = os_release.get("ID_LIKE", "").lower()
            if not distro:
                distro = os_release.get("ID", "").lower()
            return distro

        # Fallback for macOS, BSD, etc.
        return system

    # --------------------------------------------------
    # Command Registry
    # --------------------------------------------------
    def _get_commands(self) -> Dict[str, str]:
        """
        Return the install and check commands for the detected OS.

        Returns:
            Dict[str, Dict[str, str]]: OS-specific command mapping.
        """
        os_commands = {
            "arch": {
                "install": "sudo pacman -S --noconfirm ",
                "check": {
                    "qemu-img": "qemu-img",
                    "qemu-system-x86": "qemu-system-x86_64",
                },
            },
            "debian": {
                "install": "sudo apt install -y ",
                "check": {
                    "qemu-utils": "qemu-img",
                    "qemu-system-x86": "qemu-system-x86_64",
                },
            },
            "fedora": {
                "install": "dnf install -y ",
                "check": {
                    "qemu-img": "qemu-img",
                    "qemu": "qemu-system-x86_64",
                },
            },
            "gentoo": {
                "install": "sudo emerge ",
                "check": {
                    "app-emulation/qemu": "qemu-img",
                    "app-emulation/qemu": "qemu-system-x86_64",
                },
            },
            "suse": {
                "install": " sudo zypper install -y ",
                "check": {
                    "qemu-img": "qemu-img",
                    "qemu": "qemu-system-x86_64",
                },
            },
        }
        return os_commands.get(self.config.os_info or "", {})

    # --------------------------------------------------
    # OS Release Parser
    # --------------------------------------------------
    @ staticmethod
    def _get_os_release() -> Dict[str, str]:
        """
        Parse `/etc/os-release` to extract OS metadata.

        Returns:
            Dict[str, str]: Key-value pairs from the OS release file.

        Hints:
            - Provides compatibility with systems lacking
              `platform.freedesktop_os_release()`.
        """
        os_release: Dict[str, str] = {}
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        os_release[key] = value.strip('"')
        except FileNotFoundError:
            logger.warning(
                "OS release file not found; fallback behavior in use.")
        return os_release

    # p u b l i c   me t h o d s
    #
    # It does not start with an underscore (_), which means it is intended to
    # be part of the public API of the Download class.

    # --------------------------------------------------
    # Command Checking
    # --------------------------------------------------
    def check_commands(self) -> None:
        """
        Check the availability of registered commands.

        Logs:
            - DEBUG: When a command is found.
            - WARNING: When missing commands are detected.
            - ERROR: Suggests installation for missing packages.
        """
        check_dict = self.commands.get("check", {})
        missing_commands: List[str] = []

        for pkg_name, executable in check_dict.items():
            exists, path = self._check_command(executable)
            if exists:
                logger.debug(f"Found '{executable}' → {path}")
            else:
                missing_commands.append(pkg_name)
                logger.warning(f"Command '{executable}' not found in PATH.")

        if missing_commands:
            # Remove duplicate entries from a list
            missing_commands = list(dict.fromkeys(missing_commands))
            install_cmd = self.commands.get("install", "")

            logger.error(
                "Missing commands detected. "
                f"Try installing with:\n  {install_cmd}"
                f"{' '.join(missing_commands)}"
            )


# =====================================================
# Logging Configuration
# =====================================================
def configure_logging(verbosity: int = 4) -> None:
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
        "<cyan>{file}:{function}</cyan> - "
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
# CLI Entrypoint
# =====================================================
def main() -> None:

    parser = argparse.ArgumentParser(
        description="QEMU Package Detector and Installer"
    )
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
    configure_logging(args.verbose)
    logger.debug(f"Platform: {platform.system()} {platform.release()}")
    logger.debug(f"Python version: {platform.python_version()}")
    logger.debug(f"Executable path: {sys.executable}")

    # --- Assemble Config -----------------------------------------------------
    config = QemuConfig(
        verbose=args.verbose,
    )
    logger.debug(config)

    # --- Execute -------------------------------------------------------------
    detector = QemuDetector(config)


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
