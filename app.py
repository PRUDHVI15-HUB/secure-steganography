"""
app.py
──────
Flask application factory and entry point.

Responsibilities:
  - Create and configure the Flask application.
  - Ensure runtime directories exist (uploads/, outputs/).
  - Register all route Blueprints (hide, extract, analysis).
  - Register top-level routes (/, /about, /download/<filename>).
  - Register global error handlers.
  - Provide safe temporary file cleanup.

Author : CNS Lab Project
"""

import logging
import os
import time
from pathlib import Path

from flask import (
    Flask,
    abort,
    render_template,
    send_from_directory,
)
from werkzeug.utils import secure_filename

from config.settings import Config
from routes import register_blueprints


# ─── Logging ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ─── Application factory ────────────────────────────────────────────────────

def create_app() -> Flask:
    """
    Create and configure the Flask application.

    Returns:
        Configured Flask instance.
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    # ── Ensure runtime directories exist ────────────────────────────────────
    _ensure_directories(app)

    # ── Register Blueprints ─────────────────────────────────────────────────
    register_blueprints(app)

    # ── Top-level routes ────────────────────────────────────────────────────
    _register_top_level_routes(app)

    # ── Register error handlers ─────────────────────────────────────────────
    _register_error_handlers(app)

    logger.info("Application initialized successfully.")
    return app


def _ensure_directories(app: Flask) -> None:
    """Create uploads/ and outputs/ directories if they do not exist."""
    for folder_key in ("UPLOAD_FOLDER", "OUTPUT_FOLDER"):
        folder: Path = app.config[folder_key]
        folder.mkdir(parents=True, exist_ok=True)
        logger.debug("Directory ready: %s", folder)


def _register_top_level_routes(app: Flask) -> None:
    """Register the home, about, and download routes directly on the app."""

    @app.route("/")
    def index():
        """Home dashboard."""
        return render_template("index.html")

    @app.route("/about")
    def about():
        """Educational documentation and architecture details."""
        return render_template("about.html")

    @app.route("/download/<path:filename>")
    def download(filename: str):
        """
        Safely serve a generated stego PNG image for download from outputs/.
        Guards against directory traversal attacks.
        """
        output_folder: Path = Path(app.config["OUTPUT_FOLDER"]).resolve()

        # Sanitize filename and reject suspicious path characters
        safe_name = secure_filename(Path(filename).name)
        if not safe_name or ".." in filename or "/" in filename or "\\" in filename:
            logger.warning("Blocked potential path traversal attempt: %r", filename)
            abort(400)

        target_file = (output_folder / safe_name).resolve()

        # Verify the target file resolves strictly within the outputs/ directory
        try:
            if not target_file.is_relative_to(output_folder):
                logger.warning("Access denied: %s outside %s", target_file, output_folder)
                abort(400)
        except AttributeError:
            # Fallback for Python < 3.9 compatibility
            if not str(target_file).startswith(str(output_folder)):
                abort(400)

        if not target_file.exists() or not target_file.is_file():
            abort(404)

        return send_from_directory(output_folder, safe_name, as_attachment=True)


def _register_error_handlers(app: Flask) -> None:
    """Register friendly HTTP error handlers."""

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("index.html", error="Bad request: Invalid input or parameters."), 400

    @app.errorhandler(404)
    def not_found(error):
        return render_template("index.html", error="The requested page or file was not found."), 404

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return render_template(
            "index.html",
            error="The uploaded file is too large. Maximum allowed size is 16 MB.",
        ), 413

    @app.errorhandler(500)
    def internal_server_error(error):
        logger.exception("Internal server error: %s", error)
        return render_template("index.html", error="An internal server error occurred."), 500


# ─── Cleanup utility ────────────────────────────────────────────────────────

def cleanup_old_files(folder: Path, max_age_minutes: int) -> None:
    """
    Delete files in *folder* that are older than *max_age_minutes*.
    """
    if not folder.exists():
        return
    cutoff = time.time() - (max_age_minutes * 60)
    removed = 0
    for filepath in folder.iterdir():
        if filepath.is_file() and filepath.stat().st_mtime < cutoff:
            try:
                filepath.unlink()
                removed += 1
            except OSError as exc:
                logger.warning("Could not remove %s: %s", filepath, exc)
    if removed:
        logger.info("Cleaned %d old file(s) from %s", removed, folder)


# ─── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    application = create_app()

    # Run cleanup on startup for stale temporary files
    cleanup_old_files(
        application.config["UPLOAD_FOLDER"],
        application.config["TEMP_FILE_MAX_AGE_MINUTES"],
    )
    cleanup_old_files(
        application.config["OUTPUT_FOLDER"],
        application.config["TEMP_FILE_MAX_AGE_MINUTES"],
    )

    application.run(
        host="127.0.0.1",
        port=5000,
        debug=application.config["DEBUG"],
    )
