"""
routes/analysis.py
──────────────────
Blueprint for the "Security Analysis" feature.

Provides educational image metrics and capacity analytics:
  - MSE (Mean Squared Error)
  - PSNR (Peak Signal-to-Noise Ratio)
  - LSB embedding capacity breakdown
  - Payload utilization percentage

Author : CNS Lab Project
"""

import logging
import math
from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    render_template,
    request,
    session,
)

from utils.image_analysis import (
    calculate_mse,
    calculate_psnr,
    get_capacity_info,
    get_image_info,
    analyze_image_difference,
    AnalysisError,
)
from utils.validators import (
    validate_image_file,
    sanitize_filename,
    ValidationError,
)

logger = logging.getLogger(__name__)

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.route("/analysis", methods=["GET"])
def analysis():
    """
    Render the security analysis dashboard.
    Displays session metrics from the most recent hide operation if available.
    """
    last_analysis = session.get("last_analysis")
    return render_template("analysis.html", analysis=last_analysis)


@analysis_bp.route("/analysis", methods=["POST"])
def analysis_post():
    """
    Perform on-demand image quality comparison (original vs stego)
    or standalone capacity analysis.
    """
    try:
        max_size = current_app.config.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)

        original_file = request.files.get("original_image")
        stego_file = request.files.get("stego_image")

        if not original_file or not original_file.filename:
            flash("Please upload at least an original image for analysis.", "error")
            return render_template("analysis.html"), 400

        orig_bytes = original_file.read()
        orig_filename = sanitize_filename(original_file.filename)
        orig_img = validate_image_file(orig_bytes, orig_filename, max_size=max_size)

        cap_info = get_capacity_info(orig_img)

        # If a stego image is also provided, calculate MSE and PSNR comparison
        diff_info = None
        if stego_file and stego_file.filename:
            stego_bytes = stego_file.read()
            stego_filename = sanitize_filename(stego_file.filename)
            stego_img = validate_image_file(stego_bytes, stego_filename, max_size=max_size)

            diff_info = analyze_image_difference(orig_img, stego_img)

        result = {
            "original_filename": orig_filename,
            "width": orig_img.width,
            "height": orig_img.height,
            "payload_capacity": cap_info.get("payload_capacity", 0),
            "mse": diff_info.get("mse") if diff_info else 0.0,
            "psnr_display": diff_info.get("psnr_display", "N/A") if diff_info else "N/A",
            "utilization": 0.0,
            "capacity": cap_info,
            "difference": diff_info,
        }

        return render_template("analysis.html", result=result, analysis=result)

    except (ValidationError, AnalysisError) as err:
        logger.warning("Analysis error: %s", err)
        flash(str(err), "error")
        return render_template("analysis.html"), 400

    except Exception as err:
        logger.exception("Unexpected error in /analysis: %s", err)
        flash("An unexpected error occurred during image analysis.", "error")
        return render_template("analysis.html"), 500
