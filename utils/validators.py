"""
utils/validators.py
────────────────────
Input validation utilities for the secure steganography web application.

Design principles
──────────────────
• Independent of Flask request objects — accept plain Python values
  (bytes, str, Image) so each function can be unit-tested in isolation.
• Do NOT duplicate logic that belongs to other modules:
    - Capacity formula → steganography.lsb.calculate_capacity()
    - Filename sanitisation → werkzeug.utils.secure_filename()
• Raise clearly named exceptions so the Flask layer can produce
  user-friendly messages without exposing internal details.
• Do NOT store, log, or print passwords at any point.

Author : CNS Lab Project
"""

import io
import pathlib
from typing import Any, Union

from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

from steganography.lsb import calculate_capacity

# ── Import configurable size limit from project settings ──────────────────────
try:
    from config.settings import Config as _Config
    _MAX_UPLOAD_SIZE: int = _Config.MAX_CONTENT_LENGTH   # 16 MB from settings.py
except Exception:
    _MAX_UPLOAD_SIZE = 16 * 1024 * 1024                  # 16 MB fallback


# ─── Schema constants ────────────────────────────────────────────────────────

# File-extension whitelist (lowercase, with leading dot).
ALLOWED_EXTENSIONS: frozenset = frozenset({".png", ".bmp"})

# Corresponding Pillow format names — used to verify the actual file content
# is really PNG or BMP, not a JPEG file with a renamed extension.
ALLOWED_PILLOW_FORMATS: frozenset = frozenset({"PNG", "BMP"})

# Default maximum upload size (bytes).  Mirrors Config.MAX_CONTENT_LENGTH.
MAX_UPLOAD_SIZE: int = _MAX_UPLOAD_SIZE


# ─── Custom exceptions ───────────────────────────────────────────────────────

class ValidationError(Exception):
    """
    Base class for all validation errors in this module.

    The Flask layer catches ValidationError (or its subclasses) and
    displays the exception message to the user.  The message must
    therefore be user-readable — avoid technical jargon.
    """


class ImageFormatError(ValidationError):
    """
    Raised when the uploaded file has an unsupported extension or when
    Pillow detects that the file's actual format is not PNG/BMP.

    Example triggers:
        • Filename ends with .jpg / .jpeg / .gif / .tiff
        • File is renamed (e.g., image.jpeg → image.png) but bytes are JPEG
        • File has a .png extension but contains random bytes / text
    """


class FileSizeError(ValidationError):
    """
    Raised when the uploaded file exceeds MAX_UPLOAD_SIZE.
    """


class ImageContentError(ValidationError):
    """
    Raised when Pillow cannot open or decode the image data.

    Example triggers:
        • Truncated / corrupted image file
        • Zero-dimension images
        • Non-image binary data
    """


class MessageValidationError(ValidationError):
    """
    Raised when the secret message fails validation.

    Example triggers:
        • Empty string (or whitespace-only)
        • Non-string value (int, None, list …)
    """


class PasswordValidationError(ValidationError):
    """
    Raised when the encryption password fails validation.

    Note: This module does NOT enforce password complexity rules.
    The password is used purely as input to PBKDF2 key derivation.
    """


class CapacityValidationError(ValidationError):
    """
    Raised when the serialized payload exceeds the image's LSB
    embedding capacity.

    The message includes the required and available byte counts so
    the Flask layer can display helpful guidance.
    """


# ─── Image validators ────────────────────────────────────────────────────────

def validate_image_extension(filename: str) -> None:
    """
    Check that *filename* ends with an allowed extension (.png or .bmp).

    This is the first, fast check.  It is NOT sufficient on its own —
    always follow with validate_image_content() or validate_image_file().

    JPEG is deliberately excluded:
        JPEG uses lossy compression that destroys LSB modifications.
        A message hidden in a PNG stego image would be lost if that
        image were re-saved as JPEG.

    Args:
        filename : The uploaded filename string.

    Raises:
        ImageFormatError : If the extension is absent or not in ALLOWED_EXTENSIONS.
    """
    if not isinstance(filename, str) or not filename.strip():
        raise ImageFormatError("A valid filename string is required.")

    ext = pathlib.Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ImageFormatError(
            f"'{ext or '(no extension)'}' is not an accepted image format. "
            f"Please upload a PNG or BMP file. "
            f"JPEG is not supported — lossy JPEG compression would destroy "
            f"the hidden message."
        )


def validate_file_size(size_bytes: int, max_bytes: int = None) -> None:
    """
    Verify that the file size does not exceed the configured limit.

    The limit is read from Config.MAX_CONTENT_LENGTH (settings.py) and
    defaults to 16 MB.  Keeping the limit in one place avoids the need
    to update multiple files when the limit changes.

    Args:
        size_bytes : File size in bytes.
        max_bytes  : Override the default limit (optional).  Used in tests.

    Raises:
        FileSizeError : If size_bytes > max_bytes.
    """
    if max_bytes is None:
        max_bytes = MAX_UPLOAD_SIZE

    if not isinstance(size_bytes, (int, float)) or size_bytes < 0:
        raise FileSizeError(
            f"File size must be a non-negative number; got {size_bytes!r}."
        )

    if size_bytes > max_bytes:
        size_mb = size_bytes / (1024 * 1024)
        limit_mb = max_bytes / (1024 * 1024)
        raise FileSizeError(
            f"File size ({size_mb:.1f} MB) exceeds the {limit_mb:.0f} MB limit. "
            f"Please use a smaller image."
        )


def validate_image_content(image_data: Union[bytes, bytearray]) -> Image.Image:
    """
    Verify that *image_data* is a valid, openable image AND that its
    actual format is PNG or BMP (detected by Pillow, not by extension).

    Why this matters:
        A user could rename a JPEG file to 'cover.png' and upload it.
        The extension check would pass, but Pillow detects the actual
        format from the file's magic bytes and identifies it as JPEG.
        This function catches that case.

    Args:
        image_data : Raw image bytes (bytes or bytearray).

    Returns:
        The opened Pillow Image object (ready for use).

    Raises:
        ImageFormatError  : If the actual format is not PNG or BMP.
        ImageContentError : If Pillow cannot decode the data, or the
                            image has invalid dimensions.
    """
    if not isinstance(image_data, (bytes, bytearray)):
        raise ImageContentError(
            f"image_data must be bytes or bytearray; got {type(image_data).__name__!r}."
        )

    buf = io.BytesIO(bytes(image_data))

    # ── Step 1: verify() detects corruption without loading pixel data ────────
    try:
        buf.seek(0)
        probe = Image.open(buf)
        detected_format = probe.format    # read format before verify() resets it
        probe.verify()                    # raises on truncation / corruption
    except UnidentifiedImageError as exc:
        raise ImageContentError(
            "The uploaded file could not be identified as a valid image. "
            "Please ensure it is a genuine PNG or BMP file."
        ) from exc
    except Exception as exc:
        raise ImageContentError(
            f"Image verification failed — the file may be corrupted: {exc}"
        ) from exc

    # ── Step 2: Reject disallowed formats detected from actual content ────────
    # Pillow sets .format based on magic bytes (file header), not filename.
    if detected_format not in ALLOWED_PILLOW_FORMATS:
        raise ImageFormatError(
            f"The file's actual format is '{detected_format}', which is not "
            f"accepted. Only PNG and BMP images are supported. "
            f"A JPEG file with a .png extension is not a valid PNG."
        )

    # ── Step 3: Re-open and load pixel data (verify() exhausts the stream) ───
    try:
        buf.seek(0)
        image = Image.open(buf)
        image.load()   # force pixel data decode — catches partial/truncated files
    except Exception as exc:
        raise ImageContentError(
            f"Failed to load image pixel data: {exc}"
        ) from exc

    # ── Step 4: Validate dimensions ───────────────────────────────────────────
    width, height = image.size
    if width <= 0 or height <= 0:
        raise ImageContentError(
            f"Image has invalid dimensions: {width}×{height}. "
            f"Both width and height must be positive."
        )

    return image


def validate_image_file(
    image_data: bytes,
    filename: str,
    max_size: int = None,
) -> Image.Image:
    """
    Full image validation pipeline:

        1. validate_image_extension(filename)
        2. validate_file_size(len(image_data))
        3. validate_image_content(image_data)

    This is the single entry point used by the Flask HIDE and EXTRACT routes.

    Args:
        image_data : Raw bytes of the uploaded file.
        filename   : Original uploaded filename (used for extension check).
        max_size   : Override the default file size limit (optional).

    Returns:
        The validated Pillow Image object.

    Raises:
        ImageFormatError, FileSizeError, or ImageContentError.
    """
    validate_image_extension(filename)
    validate_file_size(len(image_data), max_size)
    return validate_image_content(image_data)


# ─── Message and password validators ─────────────────────────────────────────

def validate_message(message: Any) -> None:
    """
    Validate the secret message before encryption.

    Accepts any non-empty string, including Unicode (emoji, non-Latin
    scripts, multi-byte characters).  The actual byte-size constraint
    against image capacity is enforced separately by validate_payload_fits().

    Args:
        message : The secret message to validate.

    Raises:
        MessageValidationError : If the message is not a non-empty string.
    """
    if not isinstance(message, str):
        raise MessageValidationError(
            f"The secret message must be a text string; "
            f"got {type(message).__name__!r}."
        )
    # strip() catches whitespace-only strings (which would produce an empty
    # encrypted message and confuse users).
    if len(message.strip()) == 0:
        raise MessageValidationError("The secret message cannot be empty.")


def validate_password(password: Any) -> None:
    """
    Validate the encryption password.

    The password is passed to PBKDF2-HMAC-SHA256 key derivation.
    Any non-empty string is accepted.  This module does NOT:
        • Store the password
        • Log the password
        • Check password complexity (not an authentication system)

    Args:
        password : The password string to validate.

    Raises:
        PasswordValidationError : If the password is not a non-empty string.
    """
    if not isinstance(password, str):
        raise PasswordValidationError(
            f"The password must be a string; got {type(password).__name__!r}."
        )
    if len(password) == 0:
        raise PasswordValidationError("The password cannot be empty.")


# ─── Capacity validator ───────────────────────────────────────────────────────

def validate_payload_fits(payload_size: int, image: Image.Image) -> None:
    """
    Verify that *payload_size* bytes fit within the image's LSB capacity.

    Uses steganography.lsb.calculate_capacity() — does NOT duplicate the
    capacity formula (width × height × 3 ÷ 8 − 4).

    Args:
        payload_size : Number of serialized payload bytes.
        image        : The cover image (Pillow Image, any mode).

    Raises:
        CapacityValidationError : If payload_size > calculate_capacity(image).
    """
    capacity = calculate_capacity(image)
    if payload_size > capacity:
        raise CapacityValidationError(
            f"The encrypted payload ({payload_size:,} bytes) is too large "
            f"for this image (capacity: {capacity:,} bytes). "
            f"Use a larger image or a shorter message. "
            f"Need {payload_size - capacity:,} more bytes of capacity."
        )


# ─── Filename safety ──────────────────────────────────────────────────────────

def sanitize_filename(filename: str) -> str:
    """
    Return a filesystem-safe version of *filename*.

    Uses werkzeug.utils.secure_filename() to:
        • Remove path separators (prevents directory traversal)
        • Remove null bytes and control characters
        • Strip leading dots

    Examples of prevented attacks:
        ../../etc/passwd    → etcpasswd  (no traversal)
        /absolute/path.png  → absolutepath.png
        ..\\..\\win.bmp     → win.bmp

    Args:
        filename : The raw uploaded filename from the form.

    Returns:
        A sanitised filename string.  Falls back to "upload" if the
        result after sanitisation is empty.
    """
    if not isinstance(filename, str):
        return "upload"

    safe = secure_filename(filename)
    return safe if safe else "upload"
