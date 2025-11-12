#!/usr/bin/env python3
#
# -*- coding: utf-8 -*-
#
# File                  :
# Date                  : 2025-11-10 10:42:27
# Last Modified by      : a446327
# Last Modified time    : 2025-11-10 10:42:27
#
# Author:               : Christophe Vermeren <christophe.vermeren@volvo.com>
#


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
        "--kernel",
        type=str,
        default="longterm",
        help="Longterm or stable"
    )

    parser.add_argument(
        "--size",
        type=str,
        default="3G",
        help="Image size (e.g. 3G, 10G)"
    )

    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path.cwd(),
        help="Store download image into DIRECTORY."
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
        "--force",
        action="store_true",
        help="Force download even if the file exists."
    )

    parser.add_argument(
        "--minimal",
        action="store_true",
        help="Download the minimal ISO image (smaller size, fewer packages)."
    )

    parser.add_argument(
        "--skip-digest",
        action="store_true",
        help="Skip checksum validation."
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
    image_name = (
        f"manjaro-cloudimg-{downloader.iso_version}-{formatted_date}-"
        f"{kernel_versions.longterm_version}.img"
    )


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
