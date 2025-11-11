#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# File              : qemudetector.py
# Date              : 2025-11-08 09:55:21
# Last Modified time: 2025-11-11 10:05:32
#
# Author:           : Christophe Vermeren <lore.phoenix@gmail.com>
# @License          : MIT License

from __future__ import annotations

# =====================================================
# Standard library imports
# =====================================================
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Dict, Final, List, Optional, Tuple
import argparse
import platform
import shutil
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
# Enumerations
# =====================================================
class OSType(Enum):
    """Enumeration of supported operating system types."""
    ARCH = auto()
    DEBIAN = auto()
    FEDORA = auto()
    GENTOO = auto()
    RHEL = auto()
    SUSE = auto()
    WINDOWS = auto()
    UNKNOWN = auto()


# =====================================================
# Constants
# =====================================================
# --- OS Command Map ----------------------------------------------------------
OS_COMMANDS: Final[Dict[OSType, Dict[str, Dict[str, str]]]] = {
    OSType.ARCH: {
        "install": "sudo pacman -S --noconfirm ",
        "check": {
            "qemu-img": "qemu-img",
            "qemu-system-x86_64": "qemu-system-x86",
        },
    },
    OSType.DEBIAN: {
        "install": "sudo apt install -y ",
        "check": {
            "qemu-img": "qemu-utils",
            "qemu-system-x86_64": "qemu-system-x86",
        },
    },
    OSType.FEDORA: {
        "install": "sudo dnf install -y ",
        "check": {
            "qemu-img": "qemu-img",
            "qemu-system-x86_64": "qemu",
        },
    },
    OSType.GENTOO: {
        "install": "sudo emerge ",
        "check": {
            "qemu-img": "app-emulation/qemu",
            "qemu-system-x86_64": "app-emulation/qemu",
        },
    },
    OSType.RHEL: {
        "install": "sudo dnf install -y ",
        "note": (
            "Create manually a symbol link:\n  "
            "ln -s /usr/libexec/qemu-kvm /usr/bin/qemu-system-x86_64."
        ),
        "check": {
            "qemu-img": "qemu-img",
            "qemu-system-x86_64": "qemu-kvm",
        },
    },
    OSType.SUSE: {
        "install": "sudo zypper install -y ",
        "check": {
            "qemu-img": "qemu-img",
            "qemu-system-x86_64": "qemu",
        },
    },
    OSType.WINDOWS: {
        "install": "choco install -y ",
        "note": (
            "Don't forget to add into user environment PATH:\n  "
            "setx PATH \"%PATH%;C:\\Program Files\\qemu\""
        ),
        "check": {
            "qemu-img": "qemu",
            "qemu-system-x86_64": "qemu",
            "ssh": "openssh"
        },
    },
}


# =====================================================
# Data Model
# =====================================================
# slots=True Prevents dynamic attribute assignment, memory-efficient
# frozen=True Makes the instances of the class immutable after creation.
@dataclass(slots=True, frozen=True)
class QemuConfig:
    """
    Configuration options for QEMU detection and verification.

    Attributes:
        os_info (Optional[str]): Detected operating system identifier.
        verbose (int): Verbosity level (0–3).
    """
    verbose: int = 0


class QemuDetector:
    """
    A class to detect the operating system and provide QEMU package
    installation
    details.
    """

    # d u n d e r   m e t h o d s
    #
    # Methods with double underscores (e.g., __str__, __init__, __repr__) are
    # called "dunder" methods (short for "double underscore"). These are
    # special methods that Python uses for specific operations, such as string
    # representation, object initialization, etc. They are part of Python's
    # data model and are always public.

    def __init__(self, config: QemuConfig) -> None:
        """
        Initialize the QemuDetector and detect the OS.

        Args:
            config (QemuConfig): Configuration object.
        """
        self.config = config
        self._os_info: OSType = self._detect_os()
        self.commands: Dict[str, Any] = self._get_commands()

        logger.info(f"Detected OS: {self.os_info}")
        logger.trace(f"QemuDetector initialized: {self}")

        self.check_commands()

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
    def os_info(self) -> OSType:
        """Return the detected OS type."""
        return self._os_info

    # p r o t e c t e d   m e t h o d s
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
    def _detect_os(self) -> OSType:
        """
        Detect the host operating system.

        Returns:
            str: The detected OS identifier (e.g., 'windows', 'ubuntu',
                 'debian').

        Notes:
            - Uses `platform.system()` for base OS.
            - On Linux, reads `/etc/os-release` for distro ID or ID_LIKE.
        """
        system: str = platform.system().lower()

        if system == "windows":
            for os_type in OSType:
                if os_type.name.lower() == system:
                    return os_type

        if system == "linux":
            os_release: Dict[str, str] = self._get_os_release()
            major_distro: str = os_release.get("ID", "").lower()

            for os_type in OSType:
                if os_type.name.lower() == major_distro:
                    return os_type

            distro: str = os_release.get("ID_LIKE", "").lower()

            if distro:
                for os_type in OSType:
                    if os_type.name.lower() in distro.split()[0]:
                        return os_type

        return OSType.UNKNOWN

    # --------------------------------------------------
    # Command Registry
    # --------------------------------------------------
    def _get_commands(self) -> Dict[str, str]:
        """
        Return the install and check commands for the detected OS.

        Returns:
            Dict[str, Dict[str, str]]: OS-specific command mapping.
        """
        return OS_COMMANDS.get(self.os_info or "", {})

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

    # p u b l i c   m e t h o d s
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

        for executable, pkg_name in check_dict.items():
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

            message = (
                f"Missing commands detected. "
                f"Try installing with:\n  {install_cmd}"
                f"{' '.join(missing_commands)}"
            )

            if self.commands.get("note") is not None:
                message += f"\n\n{self.commands.get('note', '')}"
            logger.error(message)


# =====================================================
# CLI Entrypoint
# =====================================================
def main() -> None:

    if sys.platform == "win32":
        colorama.init(autoreset=True)
        
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
    LogSettings(args.verbose)
    logger.debug(f"Platform: {platform.system()} {platform.release()}")
    logger.debug(f"Python version: {platform.python_version()}")
    logger.debug(f"Executable path: {sys.executable}")

    # --- Assemble Config -----------------------------------------------------
    config = QemuConfig(verbose=args.verbose,)
    logger.debug(f"Loaded config: {config}")

    # --- Execute -------------------------------------------------------------
    QemuDetector(config)


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
