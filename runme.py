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
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Optional, Dict, Callable
import argparse
import platform
import subprocess
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
# Supported formats and their default options
FORMAT_OPTIONS: Dict[str, Dict[str, str]] = {
    "qcow2": {
        "preallocation": "metadata",
        "compression_type": "zstd",
    },
    "vmdk": {
        "subformat": "streamOptimized",
        "compress": "",
    },
    "raw": {},
}


def validate_input(func: Callable) -> Callable:
    """
    Decorator to validate input arguments for the run_qemu_img function.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "format" in kwargs and kwargs["format"] not in FORMAT_OPTIONS:
            raise ValueError(
                f"Unsupported format: {kwargs['format']}. "
                f"Use one of: {list(FORMAT_OPTIONS.keys())}"
            )
        return func(*args, **kwargs)
    return wrapper


@validate_input
def run_qemu_img(
    image_file: str,
    format: str = "qcow2",
    size: str = "3G",
    dry_run: bool = False,
    **custom_options: Optional[Dict[str, str]],
) -> None:
    """
    Create a QEMU disk image using qemu-img.

    Args:
        image_file: Path to the output disk image file.
        format: Disk image format (e.g., "qcow2", "vmdk", "raw").
        size: Size of the disk image (e.g., "3G", "10M").
        dry_run: If True, only log the command without executing it.
        custom_options: Custom options for the format
                        (e.g., {"preallocation": "full"}).
    """

    # Merge default and custom options
    options = FORMAT_OPTIONS[format].copy()
    options.update(custom_options)

    # Build qemu-img command
    cmd = ["qemu-img", "create", "-f", format, image_file, size]

    # Add format-specific options
    if options:
        formatted_options = list(
            f"{k}={v}" if v else k
            for k, v in options.items()
        )
        cmd.extend(["-o", ",".join(formatted_options)])

    # Dry run: log and return
    if dry_run:
        logger.info(f"[DRY RUN] Would run: {' '.join(cmd)}")
        return

    # Execute the command
    try:
        result = subprocess.run(
            cmd,
            check=True,
            text=True,
            capture_output=True,
        )
        logger.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create disk image: {e.stderr}")
        raise
    except FileNotFoundError:
        logger.error(
            "qemu-img not found. Ensure QEMU is installed and in your PATH.")
        raise


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
        "--dry-run",
        action="store_true",
        help="Simulate the download process.",
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
        "--overwrite",
        action="store_true",
        help="overwrite image if exist"
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
        dry_run=args.dry_run,
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

    if Path(f"{args.target_dir}/{image_file}").exists():
        logger.warning(f"Image file {image_file} already exist.")
    else:
        run_qemu_img(image_file, args.format, args.size, args.dry_run)

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
qemu-system-x86_64 -m 4096 -cpu kvm64 -smp 4 -drive file=manjaro-kde-25.0.10-minimal-251013-linux612.iso,media=cdrom,readonly=on -drive file=manjaro-cloudimg-25.0.10-251114-linux612.qcow2,format=qcow2  -boot d   -vga virtio -nic user,model=virtio-net-pci -name "Manjaro-live-with-cloudimg"
qemu-system-x86_64 -m 4096 -cpu kvm64 -smp 4 -drive file=manjaro-kde-25.0.10-minimal-251013-linux612.iso,media=cdrom,readonly=on -drive file=manjaro-cloudimg-25.0.10-251114-linux612.qcow2,format=qcow2  -boot d   -nographic -serial mon:stdio -nic user,model=virtio-net-pci -name "Manjaro-live-with-cloudimg"

qemu-system-x86_64 -m 4096 -cpu kvm64 -smp 4 -drive file=manjaro-kde-25.0.10-minimal-251013-linux612.iso,media=cdrom,readonly=on -drive file=manjaro-cloudimg-25.0.10-251114-linux612.qcow2,format=qcow2  -boot d  -serial tcp:127.0.0.1:6600,server,nowait -nographic -nic user,model=virtio-net-pci -name "Manjaro-live-with-cloudimg"
manjaro-cloudimg-25.0.10-yymmdd-x86_64.img

qemu-system-x86_64 -m 4096 -cpu kvm64 -smp 4 -drive file=manjaro-kde-25.0.10-minimal-251013-linux612.iso,media=cdrom,readonly=on -nic user,hostfwd=tcp::2222-:22 -boot d  -serial file:serial.log -serial stdio


qemu-system-x86_64 -m 4096 -cpu kvm64 -smp 4 -drive file=manjaro-kde-25.0.10-minimal-251013-linux612.iso,media=cdrom,readonly=on -nic user,hostfwd=tcp::2222-:22 -boot d -device virtio-serial-pci  -device virtserialport,chardev=scriptdev,name=org.qemu.script -chardev file,id=scriptdev,path=start_ssh.sh
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
