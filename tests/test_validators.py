"""
tests/test_validators.py
─────────────────────────
Automated tests for utils/validators.py.

Tests cover:
  1. Valid PNG accepted.
  2. Valid BMP accepted.
  3. JPEG extension and JPEG content rejected.
  4. Fake PNG extension containing invalid data rejected.
  5. Corrupted image rejected.
  6. Oversized file rejected.
  7. Valid message accepted.
  8. Empty message rejected.
  9. Non-string message rejected.
  10. Unicode message accepted.
  11. Empty password rejected.
  12. Non-string password rejected.
  13. Payload within capacity accepted.
  14. Payload exceeding capacity rejected.
  15. Unsafe filename handled safely.

Run with:
    pytest tests/test_validators.py -v
"""

import io
from PIL import Image
import pytest

from utils.validators import (
    validate_image_extension,
    validate_file_size,
    validate_image_content,
    validate_image_file,
    validate_message,
    validate_password,
    validate_payload_fits,
    sanitize_filename,
    ImageFormatError,
    FileSizeError,
    ImageContentError,
    MessageValidationError,
    PasswordValidationError,
    CapacityValidationError,
)


# ─── Test Helpers ────────────────────────────────────────────────────────────

def _create_image_bytes(format_name: str, mode: str = "RGB", size: tuple = (100, 100)) -> bytes:
    """Helper to generate in-memory image bytes for test fixtures."""
    img = Image.new(mode, size, color=(120, 150, 180))
    buf = io.BytesIO()
    img.save(buf, format=format_name)
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Valid PNG accepted
# ─────────────────────────────────────────────────────────────────────────────

def test_valid_png_accepted():
    png_bytes = _create_image_bytes("PNG")
    img = validate_image_file(png_bytes, "test_image.png")
    assert isinstance(img, Image.Image)
    assert img.size == (100, 100)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Valid BMP accepted
# ─────────────────────────────────────────────────────────────────────────────

def test_valid_bmp_accepted():
    bmp_bytes = _create_image_bytes("BMP")
    img = validate_image_file(bmp_bytes, "sample.bmp")
    assert isinstance(img, Image.Image)
    assert img.size == (100, 100)


# ─────────────────────────────────────────────────────────────────────────────
# 3. JPEG rejected (both extension and actual content)
# ─────────────────────────────────────────────────────────────────────────────

def test_jpeg_extension_rejected():
    with pytest.raises(ImageFormatError, match="not an accepted image format"):
        validate_image_extension("photo.jpg")

    with pytest.raises(ImageFormatError, match="not an accepted image format"):
        validate_image_extension("photo.jpeg")


def test_jpeg_content_with_png_extension_rejected():
    """A JPEG file disguised with a .png extension must be caught by content check."""
    jpeg_bytes = _create_image_bytes("JPEG")
    with pytest.raises(ImageFormatError, match="actual format is 'JPEG'"):
        validate_image_file(jpeg_bytes, "disguised.png")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Fake PNG extension containing invalid data rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_fake_png_extension_invalid_data_rejected():
    fake_data = b"This is plain text pretending to be a PNG image."
    with pytest.raises(ImageContentError):
        validate_image_file(fake_data, "fake.png")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Corrupted image rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_corrupted_png_rejected():
    valid_png = _create_image_bytes("PNG")
    # Corrupt by truncating severely
    corrupted_data = valid_png[:30]
    with pytest.raises(ImageContentError):
        validate_image_file(corrupted_data, "corrupted.png")


# ─────────────────────────────────────────────────────────────────────────────
# 6. Oversized file rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_oversized_file_rejected():
    # 2 MB limit for test override
    custom_limit = 2 * 1024 * 1024
    oversized_size = 3 * 1024 * 1024
    with pytest.raises(FileSizeError, match="exceeds"):
        validate_file_size(oversized_size, max_bytes=custom_limit)


def test_file_size_at_limit_accepted():
    limit = 1024 * 1024
    # Exactly at limit should not raise
    validate_file_size(limit, max_bytes=limit)


# ─────────────────────────────────────────────────────────────────────────────
# 7-10. Message validation
# ─────────────────────────────────────────────────────────────────────────────

def test_valid_message_accepted():
    # Should not raise
    validate_message("Confidential project report.")


def test_empty_message_rejected():
    with pytest.raises(MessageValidationError, match="cannot be empty"):
        validate_message("")

    with pytest.raises(MessageValidationError, match="cannot be empty"):
        validate_message("   \n\t  ")


def test_non_string_message_rejected():
    with pytest.raises(MessageValidationError, match="must be a text string"):
        validate_message(None)

    with pytest.raises(MessageValidationError, match="must be a text string"):
        validate_message(12345)

    with pytest.raises(MessageValidationError, match="must be a text string"):
        validate_message(b"bytes_msg")


def test_unicode_message_accepted():
    validate_message("Secret 🔐 token — नमस्ते दुनिया — 日本語")


# ─────────────────────────────────────────────────────────────────────────────
# 11-12. Password validation
# ─────────────────────────────────────────────────────────────────────────────

def test_valid_password_accepted():
    validate_password("SecurePass#1234")


def test_empty_password_rejected():
    with pytest.raises(PasswordValidationError, match="cannot be empty"):
        validate_password("")


def test_non_string_password_rejected():
    with pytest.raises(PasswordValidationError, match="must be a string"):
        validate_password(None)

    with pytest.raises(PasswordValidationError, match="must be a string"):
        validate_password(9999)


# ─────────────────────────────────────────────────────────────────────────────
# 13-14. Payload capacity validation
# ─────────────────────────────────────────────────────────────────────────────

def test_payload_within_capacity_accepted():
    # 100x100 RGB image capacity is 3,746 bytes
    img = Image.new("RGB", (100, 100))
    validate_payload_fits(500, img)
    validate_payload_fits(3746, img)


def test_payload_exceeding_capacity_rejected():
    img = Image.new("RGB", (100, 100))
    with pytest.raises(CapacityValidationError, match="too large"):
        validate_payload_fits(3747, img)


# ─────────────────────────────────────────────────────────────────────────────
# 15. Filename safety
# ─────────────────────────────────────────────────────────────────────────────

def test_sanitize_filename_traversal():
    assert sanitize_filename("../../etc/passwd.png") == "etc_passwd.png"
    assert sanitize_filename("..\\..\\secret.bmp") == "secret.bmp"
    assert sanitize_filename("/absolute/path/file.png") == "absolute_path_file.png"


def test_sanitize_filename_fallback():
    assert sanitize_filename("...") == "upload"
    assert sanitize_filename("") == "upload"
    assert sanitize_filename(None) == "upload"
