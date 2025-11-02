
#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# File              : runme.py
# Date              : 2025-11-01 14:41:27
# Last Modified time: 2025-11-02 13:54:20
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
    Match,
)
import argparse
import os
import platform
import shutil
import sys
from download import Download

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
        # Only inject a blank line before the "--checksum" argument
        if (
            hasattr(action, "option_strings")
            and "--checksum" in action.option_strings
        ):
            # Must pass a lambda that takes *no* arguments
            self._add_item(lambda: "\ndownload arguments:\n", [])
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


class Qemu():
    def __init__(self, **kwargs: Dict[str, Any]) -> None:
        
        # -----------------------
        # Initialization
        # -----------------------
        self.selected_machine: str = kwargs.get(
            "selected_machine",
            platform.machine()
        )
        self.target_dir: str = kwargs.get("target_dir", os.getcwd())
        self.verbose: int = kwargs.get("verbose", 0)

        # Initialize colorama for Windows
        if sys.platform == "win32":
            colorama.init()

        # Log system info if verbosity >= 2
        if self.verbose >= 2:
            logger.debug(f"Platform: {platform.system()} {platform.release()}")
            logger.debug(f"Python version: {platform.python_version()}")
            logger.debug(f"Executable path: {sys.executable}")



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

    # Retrieve the machine architecture (e.g., 'x86_64', 'arm64')
    machine_arch = platform.machine()

    parser = argparse.ArgumentParser(
        formatter_class=SelectiveBlankLineFormatter,
    )

    parser.add_argument(
        "-m",
        "--machine",
        type=str,
        default=machine_arch,
        help="Specify machine hardware"
    )

    parser.add_argument(
        "-t",
        "--target_dir",
        type=str,
        default=os.getcwd(),
        help="Store image into DIRECTORY."
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
        "--checksum",
        type=str,
        default="sha256",
        help="""A cryptographic hash value (e.g., MD5, SHA-1, or SHA-256) used 
to verify the integrity and authenticity of a fileSpecify a checksum hash 
value."""
    )

    parser.add_argument(
        "--environment",
        type=str,
        default="xfce",
        help=f"Specify a Desktop Environment."
    )

    parser.add_argument(
        "--minimal",
        action="store_true",
        help="Download the minimal image."
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

    activity = Qemu(
        **{
            "verbose": args.verbose,
            "selected_machine": args.machine,
            "target_dir": args.target_dir
        })
    
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
