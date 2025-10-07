"""
Logging configuration for r2morph.
"""

import logging
import sys


def setup_logging(level: str = "INFO", log_file: str | None = None):
    """
    Configure logging for r2morph.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for logging output
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    logger = logging.getLogger("r2morph")
    logger.setLevel(numeric_level)

    logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.debug(f"Logging configured: level={level}, file={log_file}")
