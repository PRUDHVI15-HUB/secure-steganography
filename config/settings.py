"""
config/settings.py
──────────────────
Central Flask configuration.

Sensitive values (SECRET_KEY) are read from environment variables so that
no credentials are ever hardcoded in source code.
"""

import os
import secrets
from pathlib import Path

# ─── Base paths ─────────────────────────────────────────────────────────────

# Absolute path to the project root (one level above this file)
BASE_DIR = Path(__file__).resolve().parent.parent

# Directories for temporary file storage
UPLOAD_FOLDER  = BASE_DIR / "uploads"
OUTPUT_FOLDER  = BASE_DIR / "outputs"

# ─── Flask configuration class ──────────────────────────────────────────────

class Config:
    """
    Default application configuration.

    In production, override SECRET_KEY via the FLASK_SECRET_KEY
    environment variable.  Never commit a real secret key to version control.
    """

    # Flask session signing key.
    # Falls back to a random key for development; this means sessions reset
    # on every server restart — acceptable for a demo application.
    SECRET_KEY: str = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

    # ── Upload / output paths ────────────────────────────────────────────────
    UPLOAD_FOLDER:  Path = UPLOAD_FOLDER
    OUTPUT_FOLDER:  Path = OUTPUT_FOLDER

    # Maximum upload size: 16 MB
    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024

    # Allowed image extensions for input
    ALLOWED_EXTENSIONS: set = {"png", "bmp"}

    # ── Temporary file cleanup ───────────────────────────────────────────────
    # Files older than this many minutes will be removed on the next request
    TEMP_FILE_MAX_AGE_MINUTES: int = 30

    # ── Debug mode ──────────────────────────────────────────────────────────
    # Set FLASK_DEBUG=1 in the environment to enable debug mode
    DEBUG: bool = os.environ.get("FLASK_DEBUG", "0") == "1"
