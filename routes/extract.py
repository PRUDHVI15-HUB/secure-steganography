"""
routes/extract.py
─────────────────
Blueprint for the "Extract Message" feature.

Workflow:
  1. Validate uploaded stego image (format, size, content).
  2. Extract raw embedded bytes using LSB steganography (steganography/lsb.py).
  3. Parse and validate versioned JSON payload (utils/payload.py).
  4. Decode Base64 cryptographic components (salt, nonce, ciphertext).
  5. Recompute SHA-256 digest of (salt ‖ nonce ‖ ciphertext).
  6. Verify integrity using constant-time comparison (hmac.compare_digest).
     - If integrity verification FAILS: halt and do NOT attempt decryption.
  7. Decrypt ciphertext using AES-256-GCM + PBKDF2 (crypto/encryption.py).
     - Wrong password or tag corruption raises DecryptionError.
  8. Return extracted secret message and cryptographic verification details.

Author : CNS Lab Project
"""

import hmac
import logging

from flask import (
    Blueprint,
    current_app,
    flash,
    render_template,
    request,
)

from crypto.encryption import decrypt_message, DecryptionError
from crypto.hashing import sha256_components
from steganography.lsb import extract_payload, ExtractionError, SteganographyError
from utils.payload import parse_payload, decode_payload_fields, PayloadError
from utils.validators import (
    validate_image_file,
    validate_password,
    sanitize_filename,
    ValidationError,
)

logger = logging.getLogger(__name__)

extract_bp = Blueprint("extract", __name__)


@extract_bp.route("/extract", methods=["GET"])
def extract_get():
    """Render the extract-message form."""
    return render_template("extract.html")


@extract_bp.route("/extract", methods=["POST"])
def extract_post():
    """
    Handle stego image upload, LSB extraction, SHA-256 verification, and AES decryption.
    """
    try:
        # ── 1. Check and retrieve uploaded stego image ────────────────────────
        file_obj = request.files.get("image") or request.files.get("stego_image")
        if not file_obj or not file_obj.filename:
            flash("Please select a stego image file to upload.", "error")
            return render_template("extract.html"), 400

        filename = sanitize_filename(file_obj.filename)
        file_bytes = file_obj.read()

        if not file_bytes:
            flash("The uploaded file is empty. Please select a valid stego image.", "error")
            return render_template("extract.html"), 400

        # ── 2. Validate image format and content ──────────────────────────────
        max_size = current_app.config.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)
        stego_image = validate_image_file(file_bytes, filename, max_size=max_size)

        # ── 3. Validate password ──────────────────────────────────────────────
        password = request.form.get("password", "")
        validate_password(password)

        # ── 4. Extract raw payload bytes from LSBs ────────────────────────────
        try:
            raw_payload_bytes = extract_payload(stego_image)
        except ExtractionError as exc:
            logger.warning("LSB extraction failed: %s", exc)
            flash("No valid hidden message was found in this image.", "error")
            return render_template("extract.html"), 400

        # ── 5. Parse and decode versioned payload ─────────────────────────────
        try:
            payload_dict = parse_payload(raw_payload_bytes)
            decoded_fields = decode_payload_fields(payload_dict)
        except PayloadError as exc:
            logger.warning("Payload parsing failed: %s", exc)
            flash("The hidden data structure is invalid or corrupted.", "error")
            return render_template("extract.html"), 400

        # ── 6. SHA-256 Integrity Verification ─────────────────────────────────
        # Recalculate SHA-256 over (salt ‖ nonce ‖ ciphertext)
        computed_digest = sha256_components(
            decoded_fields["salt"],
            decoded_fields["nonce"],
            decoded_fields["ciphertext"],
        )

        stored_digest = decoded_fields["sha256"]

        # Constant-time comparison prevents timing attacks
        integrity_valid = hmac.compare_digest(computed_digest, stored_digest)

        if not integrity_valid:
            logger.warning("SHA-256 integrity mismatch detected on extraction.")
            flash(
                "Integrity verification failed! The image or payload has been tampered with or corrupted.",
                "error",
            )
            return render_template(
                "extract.html",
                integrity_failed=True,
                computed_hash=computed_digest.hex(),
                stored_hash=stored_digest.hex(),
            ), 400

        # ── 7. AES-256-GCM Decryption ─────────────────────────────────────────
        try:
            decrypted_message = decrypt_message(decoded_fields, password)
        except DecryptionError as exc:
            logger.warning("Decryption failed: %s", exc)
            flash("Incorrect password or encrypted data could not be authenticated.", "error")
            return render_template("extract.html"), 400

        # ── 8. Success response ───────────────────────────────────────────────
        flash("Message extracted and decrypted successfully.", "success")
        return render_template(
            "extract.html",
            success=True,
            message=decrypted_message,
            sha256_hex=computed_digest.hex(),
            algorithm=decoded_fields.get("algorithm", "AES-256-GCM"),
            kdf=decoded_fields.get("kdf", "PBKDF2-HMAC-SHA256"),
            iterations=decoded_fields.get("iterations", 600000),
            integrity_verified=True,
            auth_verified=True,
        )

    except ValidationError as err:
        logger.warning("Validation error in /extract: %s", err)
        flash(str(err), "error")
        return render_template("extract.html"), 400

    except SteganographyError as err:
        logger.warning("Steganography error in /extract: %s", err)
        flash(str(err), "error")
        return render_template("extract.html"), 400

    except Exception as err:
        logger.exception("Unexpected error in /extract: %s", err)
        flash("An unexpected error occurred while extracting the message.", "error")
        return render_template("extract.html"), 500
