"""
Custom Logging Setup Module

Provides a configurable logging utility class that sets up a console and file logger
with a unified formatter.

Author: Sai Vignesh
Date: 14/05/2025
"""

import logging
from logging.handlers import RotatingFileHandler
import os
import tempfile
from auth.config import get_env_var

def setup_logging():
    """
    Initialize the logger with file-based rotating logging.
    Returns:
        Logger object with RotatingFileHandler attached.
    """
    # Temp log dir
    log_dir = os.path.join(tempfile.gettempdir(), "CryptVault")
    os.makedirs(log_dir, exist_ok=True)

    # Log file path
    log_file_path = os.path.join(log_dir, get_env_var('LOG_FILE'))

    # Create logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False  # To prevent duplicate logs

    # Check if handlers already added
    if not logger.handlers:
        # Rotating File Handler
        file_handler = RotatingFileHandler(
            log_file_path, maxBytes=100000, backupCount=3
        )
        file_handler.setLevel(logging.DEBUG)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)


        # Add handlers
        logger.addHandler(file_handler)

    return logger
