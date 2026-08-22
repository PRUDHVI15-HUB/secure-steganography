"""
routes/hide.py
──────────────
Blueprint for the "Hide Message" feature.

Workflow:
  1. Validate uploaded cover image (format, size, content).
  2. Validate secret message and password confirmation.
  3. Encrypt secret message with AES-256-GCM + PBKDF2-HMAC-SHA256.
  4. Compute SHA-256 integrity digest of (salt ‖ nonce ‖ ciphertext).
  5. Assemble versioned JSON payload and serialize to compact bytes.
  6. Verify payload fits inside image embedding capacity.
  7. Embed payload bits into image RGB channels using LSB steganography.
  8. Save stego image as a PNG in outputs/ with a secure random filename.
  9. Calculate image quality metrics (MSE, PSNR, payload utilization).
  10. Return success response with download link and analysis summary.

Security:
  - Passwords, derived keys, and plaintexts are NEVER stored in sessions,
    logged, or exposed in output files.
  - Original uploaded files are processed in-memory / discarded cleanly.

Author : CNS Lab Project
"""

import hmac
import logging
import math
import uuid
from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from crypto.encryption import encrypt_message, DecryptionError
from crypto.hashing import sha256_components, sha256_components_hex
from steganography.lsb import (
    embed_payload,
    calculate_capacity,
    CapacityError,
    SteganographyError,
)
from utils.image_analysis import (
    calculate_mse,
    calculate_psnr,
    get_capacity_info,
    calculate_payload_utilization,
    get_image_info,
)
from utils.payload import (
    build_payload,
    serialize_payload,
    PayloadError,
)
from utils.validators import (
    validate_image_file,
    validate_message,
    validate_password,
    validate_payload_fits,
    sanitize_filename,
    ValidationError,
)

logger = logging.getLogger(__name__)

hide_bp = Blueprint("hide", __name__)


@hide_bp.route("/hide", methods=["GET"])
def hide_get():
    """Render the hide-message form."""
    return render_template("hide.html")


@hide_bp.route("/hide", methods=["POST"])
def hide_post():
    """
    Handle cover image upload, secret message encryption, and LSB embedding.
    """
    try:
        # ── 1. Check and retrieve uploaded file ───────────────────────────────
        if "image" not in request.files:
            flash("Please select an image file to upload.", "error")
            return render_template("hide.html"), 400

        file_obj = request.files["image"]
        if not file_obj or not file_obj.filename:
            flash("No file was selected. Please choose a PNG or BMP image.", "error")
            return render_template("hide.html"), 400

        original_filename = sanitize_filename(file_obj.filename)
        file_bytes = file_obj.read()

        if not file_bytes:
            flash("The uploaded file is empty. Please select a valid image.", "error")
            return render_template("hide.html"), 400

        # ── 2. Validate image format, size, and content ───────────────────────
        max_size = current_app.config.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)
        cover_image = validate_image_file(file_bytes, original_filename, max_size=max_size)

        # ── 3. Validate form inputs (message & passwords) ──────────────────────
        message = request.form.get("message", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        validate_message(message)
        validate_password(password)

        if password != confirm_password:
            flash("Passwords do not match. Please re-enter your password.", "error")
            return render_template("hide.html"), 400

        # ── 4. Cryptographic pipeline ─────────────────────────────────────────
        # Phase 2: Derive key via PBKDF2-HMAC-SHA256 and encrypt via AES-256-GCM
        encrypted_data = encrypt_message(message, password)

        # Phase 3: Compute SHA-256 integrity hash over (salt ‖ nonce ‖ ciphertext)
        digest = sha256_components(
            encrypted_data["salt"],
            encrypted_data["nonce"],
            encrypted_data["ciphertext"],
        )

        # Phase 4: Assemble versioned JSON payload and serialize to deterministic bytes
        payload_dict = build_payload(encrypted_data, digest)
        payload_bytes = serialize_payload(payload_dict)

        # ── 5. Steganographic embedding ───────────────────────────────────────
        # Phase 6 / Phase 5: Verify capacity and embed payload bits
        validate_payload_fits(len(payload_bytes), cover_image)
        stego_image = embed_payload(cover_image, payload_bytes)

        # ── 6. Save generated stego image ─────────────────────────────────────
        output_folder: Path = current_app.config["OUTPUT_FOLDER"]
        output_folder.mkdir(parents=True, exist_ok=True)

        stego_filename = f"stego_{uuid.uuid4().hex[:12]}.png"
        output_filepath = output_folder / stego_filename
        stego_image.save(output_filepath, format="PNG")

        # ── 7. Image quality and capacity analysis ────────────────────────────
        mse = calculate_mse(cover_image, stego_image)
        psnr = calculate_psnr(mse)
        cap_info = get_capacity_info(cover_image)
        utilization = calculate_payload_utilization(
            len(payload_bytes), cap_info["payload_capacity"]
        )

        psnr_display = "∞ (identical images)" if math.isinf(psnr) else f"{psnr:.2f} dB"

        analysis_result = {
            "stego_filename": stego_filename,
            "original_filename": original_filename,
            "width": cover_image.width,
            "height": cover_image.height,
            "mse": round(mse, 6),
            "psnr": psnr if not math.isinf(psnr) else None,
            "psnr_display": psnr_display,
            "payload_bytes": len(payload_bytes),
            "payload_capacity": cap_info["payload_capacity"],
            "utilization": round(utilization, 2),
            "sha256_hex": digest.hex(),
        }

        # Store analysis summary in session for the /analysis view
        session["last_analysis"] = analysis_result

        flash("Message encrypted and hidden successfully into the image.", "success")
        return render_template(
            "hide.html",
            success=True,
            result=analysis_result,
        )

    except ValidationError as err:
        logger.warning("Validation error in /hide: %s", err)
        flash(str(err), "error")
        return render_template("hide.html"), 400

    except SteganographyError as err:
        logger.warning("Steganography error in /hide: %s", err)
        flash(str(err), "error")
        return render_template("hide.html"), 400

    except Exception as err:
        logger.exception("Unexpected error in /hide: %s", err)
        flash("An unexpected error occurred while processing your request.", "error")
        return render_template("hide.html"), 500
