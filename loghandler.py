#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File              : loghandler.py
# Date              : 2025-11-10 15:05:38
# Last Modified time: 2025-11-10 15:18:24
#
# Author:           : Christophe Vermeren <christophe.vermeren@volvo.com>
# @License          : MIT License

from __future__ import annotations

# =====================================================
# Standard library imports
# =====================================================
from collections import deque
import sys

# =====================================================
# Third-party imports
# =====================================================
from loguru import logger

# =====================================================
# Constants
# =====================================================
LOG_BUFFER: deque[str] = deque(maxlen=1000)  # Buffer for log messages


# =====================================================
# Logging Helpers
# =====================================================
class LogBufferHandler:
    """
    Custom callable class to store log messages in a deque buffer.

    This is particularly useful when:
    - Logs need to be retained for later processing or inspection.
    - Real-time logging to console or file is not desired.
    - Debugging in environments like Jupyter notebooks, GUI apps, or serverless
      functions.

    Attributes
    ----------
    buffer : deque[str]
        Reference to a global log buffer to accumulate log messages.
    """

    def __init__(self) -> None:
        """Initialize the log buffer handler."""
        self.buffer: deque[str] = LOG_BUFFER

    def __call__(self, message: str) -> None:
        """
        Append a log message to the buffer.

        Parameters
        ----------
        message : str
            The formatted log message from `loguru`.
        """
        self.buffer.append(message)


class LogSettings:
    """
    Configure and manage logging settings using `loguru`.

    Provides:
    - Verbosity-based log levels.
    - Optional in-memory buffering of log messages for extreme verbosity.
    - Custom log formatting with time, level, file, function, and message.

    Parameters
    ----------
    verbosity : int, optional
        Level of verbosity from 0 (WARNING) to 4 (TRACE + buffer),
        by default 4.
    """

    def __init__(self, verbosity: int = 4) -> None:
        # Mapping verbosity levels to loguru levels
        log_levels = {
            0: "WARNING",   # Show only warnings and errors
            1: "INFO",     # Informational messages
            2: "DEBUG",    # Debug messages for developers
            3: "TRACE",    # Fine-grained trace of program execution
        }

        # Default to TRACE for unknown verbosity
        level: str = log_levels.get(verbosity, "TRACE")

        # Log format: timestamp | level | file::function - message
        # Using colors for terminal output (works in most terminals)
        log_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{file}::{function}</cyan> - "
            "<level>{message}</level>"
        )

        # Remove any pre-configured loggers to avoid duplicates
        logger.remove()

        # Add console logging handler
        logger.add(sys.stderr, level=level, format=log_format)

        # If verbosity is very high, also log to the in-memory buffer
        if verbosity > 3:
            log_buffer_handler = LogBufferHandler()
            logger.add(log_buffer_handler, level="TRACE", format=log_format)


# =====================================================
# CLI Entrypoint
# =====================================================
def main() -> None:
    # Initialize logging with maximum verbosity
    LogSettings(verbosity=4)

    # Example log messages
    logger.error("This is an error message.")
    logger.warning("This is a warning message.")
    logger.info("This is an info message.")
    logger.debug("Debugging details here.")
    logger.trace("Trace-level logging for deep inspection.")


# ====================================
# Usage Example
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
