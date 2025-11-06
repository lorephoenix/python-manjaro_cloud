
#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# File              : runme.py
# Date              : 2025-11-01 14:41:27
# Last Modified time: 2025-11-06 22:13:59
#
# Author:           : Christophe Vermeren <lore.phoenix@gmail.com>
# @License          : MIT License

"""
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
    Tuple,
    Match,
)
import argparse
import os
import platform
import shutil
import sys
from download import Download, DownloadConfig

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


class QEMUDetector:
    def __init__(self):
        self.os_info = self._detect_os()
        self.commands = self._get_commands()

        

    def _detect_os(self) -> str:
        """Detect the OS and return a string identifier."""
        system = platform.system().lower()
        if system == "linux":
            distro = platform.freedesktop_os_release().get("ID", "").lower()
            return distro
        return system

    def _get_commands(self) -> Dict[str, str]:
        """Return the install and check commands for the detected OS."""
        os_commands = {
            "alpine": {
                "install": "sudo apk add qemu qemu-img qemu-system-x86_64",
                "check": ["qemu-img", "qemu-system-x86_64"],
            },
            "arch": {
                "install": "sudo pacman -S --noconfirm qemu qemu-img",
                "check": ["qemu-img", "qemu-system-x86_64"],
            },
            "manjaro": {
                "install": "sudo pacman -S --noconfirm qemu qemu-img",
                "check": ["qemu-img", "qemu-system-x86_64"],
            },
            "debian": {
                "install": "sudo apt install -y qemu-system qemu-utils",
                "check": ["qemu-img", "qemu-system-x86_64"],
            },
            "ubuntu": {
                "install": "sudo apt install -y qemu-system qemu-utils",
                "check": ["qemu-img", "qemu-system-x86_64"],
            },
            "fedora": {
                "install": "sudo dnf install -y qemu qemu-img",
                "check": ["qemu-img", "qemu-system-x86_64"],
            },
            "gentoo": {
                "install": "sudo emerge --ask app-emulation/qemu",
                "check": ["qemu-img", "qemu-system-x86_64"],
            },
            "opensuse": {
                "install": "sudo zypper install -y qemu qemu-img",
                "check": ["qemu-img", "qemu-system-x86_64"],
            },
            "suse": {
                "install": "sudo zypper install -y qemu qemu-img",
                "check": ["qemu-img", "qemu-system-x86_64"],
            },
        }
        return os_commands.get(self.os_info, {})

    def get_install_command(self) -> Optional[str]:
        """Return the install command for the detected OS."""
        return self.commands.get("install")

    def check_commands(self) -> Dict[str, Tuple[bool, Optional[str]]]:
        """
        Check if the QEMU commands exist in PATH.
        Returns a dictionary with command names as keys and tuples of (exists, path).
        """
        results = {}
        for cmd in self.commands.get("check", []):
            exists, path = self.check_command(cmd)
            results[cmd] = (exists, path)
        return results

    @staticmethod
    def check_command(command: str) -> Tuple[bool, Optional[str]]:
        """Check if a command exists in PATH."""
        path = shutil.which(command)
        if path:
            return True, path
        return False, None

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
# CLI Entrypoint
# =====================================================
def main() -> None:

    logger.debug(f"Platform: {platform.system()} {platform.release()}")
    logger.debug(f"Python version: {platform.python_version()}")
    logger.debug(f"Executable path: {sys.executable}")
    
    parser = argparse.ArgumentParser(
        formatter_class=SelectiveBlankLineFormatter,
        description="....",
    )

    # --- Arguments -----------------------------------------------------------
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Force download even if the file exists."
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
        "--environment",
        type=str,
        default="kde",
        help="Desktop environment (e.g., xfce, kde, gnome)."
    )

    parser.add_argument(
        "-m",
        "--minimal",
        action="store_true",
        help="Download the minimal ISO image (smaller size, fewer packages)."
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

    
    # --- Assemble Config -----------------------------------------------------
    config = DownloadConfig(
        environment=args.environment,
        digest=args.digest,
        force=args.force,
        minimal=args.minimal,
        skip_digest=args.skip_digest,
        target_dir=args.target_dir,
        verbose=args.verbose,
        verify_ssl=args.no_verify_ssl,
    )

    detector = QEMUDetector()
    sys.exit(0)    

    """
    # --- Execute -------------------------------------------------------------
    try:
        downloader = Download(config)

    except DownloadError as e:
        logger.error(f"Download failed: {e}")
        sys.exit(1)
    """
    detector = QEMUDetector()
    print(f"Detected OS: {detector.os_info}")
    print(f"Install command: {detector.get_install_command()}")
    print("Command checks:")
    for cmd, (exists, path) in detector.check_commands().items():
        print(f"  {cmd}: {'Exists' if exists else 'Not found'}")


    # Initialize Download
    """
    tt = Download(
        **{
            "verbose": args.verbose,
            "checksum": args.checksum,
            "dry_run": args.dry_run,
            "environment": args.environment,
            "force": args.force,
            "minimal": args.minimal,
            "selected_machine": args.machine,
            "target_dir": args.target_dir
        })
    """


# ====================================
# Script Entry Point
# ====================================
if __name__ == "__main__":
    main()


'''
# Retrieve the machine architecture (e.g., 'x86_64', 'arm64')
    machine_arch = platform.machine()

    distro, distro_like = detect_os()
    has_qemu_img, qemu_img_path = check_command("qemu-img")
    has_qemu_system, qemu_system_path = check_command("qemu-system-x86_64")

    distro_lower = distro.lower()
    distro_like_lower = (distro_like or "").lower()
    
Alpine
    sudo apk add qemu qemu-img qemu-system-x86_64
    qemu-img
    qemu-system-x86_64

Arch/Manjaro
    sudo pacman -S --noconfirm qemu qemu-img 
    qemu-img
    qemu-system-x86_64

debian/ubuntu
    sudo apt install -y qemu-system qemu-utils
    qemu-img
    qemu-system-x86_64
    
fedora
    sudo dnf install -y qemu qemu-img
    qemu-img
    qemu-system-x86_64

gentoo
    sudo emerge --ask app-emulation/qemu
    qemu-img
    qemu-system-x86_64
    
opensuse/suse
    sudo zypper install -y qemu qemu-img
    qemu-img
    qemu-system-x86_64

def check_command(command: str):
    """Check if a command exists in PATH."""
    path = shutil.which(command)
    if path:
        return True, path
    return False, None


def detect_os():
    """Detect the OS name and distro family using ID and ID_LIKE."""
    system = platform.system()

    if system == "Windows":
        return "Windows", None

    if system == "Linux":
        info = parse_os_release()
        distro_id = info.get("ID", "").lower()
        distro_like = info.get("ID_LIKE", "").lower()

        if distro_id:
            return distro_id.capitalize(), distro_like or None
        else:
            return "Linux (unknown distro)", None

    return system, None


def parse_os_release():
    """Parse /etc/os-release into a dict if it exists."""
    os_release = Path("/etc/os-release")
    info = {}
    if os_release.exists():
        with open(os_release, "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    info[key] = value.strip('"')
    return info
'''
