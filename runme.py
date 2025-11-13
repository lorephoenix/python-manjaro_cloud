#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# File              : runme.py
# Date              : 2025-11-01 14:41:27
# Last Modified time: 2025-11-13 19:48:15
#
# Author:           : Christophe Vermeren <lore.phoenix@gmail.com>
# @License          : MIT License

from __future__ import annotations

# =====================================================
# Standard library imports
# =====================================================
from collections import deque
from datetime import datetime
from pathlib import Path
import argparse
import platform
import sys

# =====================================================
# Third-party imports
# =====================================================
from loguru import logger
import colorama

# =====================================================
# My imports
# =====================================================
from download import (
    Download, DownloadConfig, DownloadError, SelectiveBlankLineFormatter
)
from kernel import KernelConfig, LinuxKernelVersions
from loghandler import LogSettings
from qemudetector import QemuConfig, QemuDetector


# =====================================================
# Constants
# =====================================================

def ask_confirmation(prompt: str = "Do you want to continue? (y/N): ") -> bool:
    """
    Ask the user whether to proceed with an action.

    Args:
        prompt (str): The confirmation question (default = "Do you want to continue? (y/N): ").

    Returns:
        bool: True if the user confirms ('y' or 'Y'), False otherwise.
    """
    answer = input(prompt).strip().lower()
    return answer == "y"

def test(image_file: str, noconfirm: bool = False) -> bool:

    if Path(image_file).exists:
        logger.warning(f"Image file {image_file} already exist.")
        if not noconfirm:
            if ask_confirmation("Do you want to recreate the image? (y/N): "):

                print("Proceeding with action...")
                # Your action here, e.g. delete files
            else:
                print("Action canceled.")
    return True


# =====================================================
# CLI Entrypoint
# =====================================================
def main() -> None:

    if sys.platform == "win32":
        colorama.init(autoreset=True)

    parser = argparse.ArgumentParser(
        formatter_class=SelectiveBlankLineFormatter,
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="""increase output verbosity. Use multiple times for more detail
(e.g., -vvv)."""
    )

    parser.add_argument(
        "--format",
        type=str,
        choices=["qcow2", "raw", "vmdk"],
        default="qcow2",
        help="choose image format: 'qcow2', 'raw' or 'vmdk'"
    )

    parser.add_argument(
        "--kernel",
        type=str,
        choices=["longterm", "stable"],
        default="longterm",
        help="choose kernel type: 'longterm' or 'stable'"
    )

    parser.add_argument(
        "--noconfirm",
        action="store_true",
        help="do not ask for any confirmation"
    )

    parser.add_argument(
        "--size",
        type=str,
        default="3G",
        help="image size (e.g. 3G, 10G)"
    )

    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path.cwd(),
        help="store download image into DIRECTORY."
    )

    parser.add_argument(
        "--digest",
        type=str,
        default="sha256",
        help="""a cryptographic hash value (e.g., MD5, SHA-1, or SHA-256) used
to verify the integrity and authenticity of a fileSpecify a checksum hash
value."""
    )

    parser.add_argument(
        "--environment",
        type=str,
        default="kde",
        help="desktop environment (e.g., xfce, kde, gnome)."
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="force download even if the file exists."
    )

    parser.add_argument(
        "--minimal",
        action="store_true",
        help="download the minimal ISO image (smaller size, fewer packages)."
    )

    parser.add_argument(
        "--skip-digest",
        action="store_true",
        help="skip checksum validation."
    )

    args = parser.parse_args()


    # --- Initialize Logging --------------------------------------------------
    LogSettings(args.verbose)
    logger.debug(f"Platform: {platform.system()} {platform.release()}")
    logger.debug(f"Python version: {platform.python_version()}")
    logger.debug(f"Executable path: {sys.executable}")

    # --- Assemble Config -----------------------------------------------------
    download_config = DownloadConfig(
        environment=args.environment,
        digest=args.digest,
        force=args.force,
        minimal=args.minimal,
        skip_digest=args.skip_digest,
        target_dir=args.target_dir,
        verbose=args.verbose,
    )

    kernel_config = KernelConfig(verbose=args.verbose,)
    logger.debug(f"Loaded config: {kernel_config}")

    qemu_config = QemuConfig(verbose=args.verbose,)
    logger.debug(f"Loaded Download config: {download_config}")
    logger.debug(f"Loaded Qemu config: {qemu_config}")

    # --- Execute -------------------------------------------------------------
    kernel_versions = LinuxKernelVersions(kernel_config)
    if args.kernel.lower() == "longterm":
        kernel_version = kernel_versions.longterm_version
    else:
        kernel_version = kernel_versions.stable_version

    version_list = kernel_version.split(".")
    kernel_package = "linux" + "".join(version_list[:2])
    logger.debug(
        f"Kernel version: {kernel_version} "
        f"Kernel package: {kernel_package}")

    QemuDetector(qemu_config)

    try:
        downloader = Download(download_config)
        downloader.download()
        downloader.validate_checksum()
        print(downloader.iso_version)
    except DownloadError as e:
        logger.error(f"Download failed: {e}")
        sys.exit(1)

    # Get current date
    current_date = datetime.now()

    # Format as YYMMdd
    formatted_date = current_date.strftime("%y%m%d")
    image_name: str = (
        f"manjaro-cloudimg-{downloader.iso_version}-{formatted_date}-"
        f"{kernel_package}"
    )

    image_file: str = f"{image_name}.{args.format}"
    image_digest: str = f"{image_name}.{args.format}.{args.digest}"

    if test(image_file, args.noconfirm):
        print("action")
    else:
        print("noaction")
    

    
        # check is img, qcow2, vmdk and sha256 exist of image
        # if exist then when using args.force remove files or overwritten files

    sys.exit(0)


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
"""

qemu-img create -f raw  test.raw 3G
qemu-img create -f qcow2 -o compression_type=zstd,preallocation=metadata test.qcow2 3G
qemu-img create -f vmdk -o subformat=streamOptimized,compress test.vmdk 3G

manjaro-cloudimg-25.0.10-yymmdd-x86_64.img

stable <> longterm (LTS)

"""
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
