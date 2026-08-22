"""
utils/image_analysis.py
────────────────────────
Educational image quality metrics and capacity analysis.

This module provides MSE, PSNR, and capacity information for the
CNS lab project's analysis display.

Design notes
─────────────
• MSE and PSNR compare RGB pixel data directly from Pillow arrays.
  No JPEG recompression step is introduced, so the metrics accurately
  reflect only the LSB modification — not JPEG artefacts.

• Capacity metrics delegate to steganography.lsb.calculate_capacity()
  and do NOT duplicate the LSB formula.

• This module does NOT modify image data.  It only reads pixel arrays.

• float("inf") is returned for PSNR when MSE == 0 (identical images).
  Do NOT replace infinity with an arbitrary number like 999 — that would
  misrepresent the mathematics in an academic project.

Author : CNS Lab Project
"""

import math
from typing import Optional

import numpy as np
from PIL import Image

from steganography.lsb import calculate_capacity


# ─── Custom exception ─────────────────────────────────────────────────────────

class AnalysisError(Exception):
    """
    Raised when image analysis cannot be completed.

    Example: calculate_mse() called with images of different dimensions.
    """


# ─── Image information ────────────────────────────────────────────────────────

# Maps Pillow mode strings to channel counts.
_MODE_CHANNELS: dict = {
    "1": 1, "L": 1, "P": 1,
    "RGB": 3, "RGBA": 4, "CMYK": 4,
    "YCbCr": 3, "LAB": 3, "HSV": 3,
    "LA": 2, "PA": 2,
    "I": 1, "F": 1,
}


def get_image_info(
    image: Image.Image,
    file_size: Optional[int] = None,
) -> dict:
    """
    Return a dictionary of descriptive metadata for a Pillow Image.

    Does NOT modify the image.

    Args:
        image     : Any Pillow Image object.
        file_size : Optional on-disk file size in bytes (from upload context).

    Returns:
        {
            "width":        int,
            "height":       int,
            "mode":         str,          e.g. "RGB", "RGBA"
            "channels":     int,          number of channels in the native mode
            "format":       str | None,   Pillow format string, or None
            "total_pixels": int,
            "file_size_bytes": int,       only if file_size was provided
            "file_size_kb":    float,     only if file_size was provided
        }
    """
    width, height = image.size
    channels = _MODE_CHANNELS.get(image.mode, len(image.getbands()))

    info: dict = {
        "width":        width,
        "height":       height,
        "mode":         image.mode,
        "channels":     channels,
        "format":       image.format,   # None for in-memory images
        "total_pixels": width * height,
    }

    if file_size is not None:
        info["file_size_bytes"] = file_size
        info["file_size_kb"]    = round(file_size / 1024, 2)

    return info


# ─── MSE ─────────────────────────────────────────────────────────────────────

def calculate_mse(original: Image.Image, stego: Image.Image) -> float:
    """
    Calculate the Mean Squared Error between two images.

    Both images are converted to RGB before comparison.  This normalises
    alpha channels and colour-space differences, giving a fair comparison
    for LSB steganography where only the RGB channels are modified.

    Formula:
        MSE = (1 / N) × Σ (original_i − stego_i)²

    where N is the total number of channel values (W × H × 3).

    Args:
        original : The cover image before LSB embedding.
        stego    : The stego image after LSB embedding.

    Returns:
        MSE as a float.  Returns 0.0 for identical images.

    Raises:
        AnalysisError : If image dimensions differ (silent resizing is
                        intentionally NOT performed — it would invalidate
                        the MSE calculation).
    """
    orig_rgb  = original.convert("RGB")
    stego_rgb = stego.convert("RGB")

    if orig_rgb.size != stego_rgb.size:
        raise AnalysisError(
            f"Image dimensions must match for MSE calculation. "
            f"Original: {orig_rgb.size[0]}×{orig_rgb.size[1]}, "
            f"stego: {stego_rgb.size[0]}×{stego_rgb.size[1]}. "
            f"Do not resize images before comparison."
        )

    orig_arr  = np.array(orig_rgb,  dtype=np.float64)
    stego_arr = np.array(stego_rgb, dtype=np.float64)

    return float(np.mean((orig_arr - stego_arr) ** 2))


# ─── PSNR ─────────────────────────────────────────────────────────────────────

def calculate_psnr(mse: float, max_pixel_value: int = 255) -> float:
    """
    Calculate the Peak Signal-to-Noise Ratio from a pre-computed MSE.

    Formula:
        PSNR = 10 × log₁₀( MAX² / MSE )

    For MSE == 0 (identical images), returns float("inf").
    Do NOT replace infinity with an arbitrary constant such as 999 —
    that misrepresents the mathematics.

    Typical values for LSB steganography on 8-bit RGB images:
        • 1 LSB modification on all channels → ~48–51 dB
        • Higher PSNR → less visible distortion
        • PSNR > 40 dB is generally considered imperceptible to the human eye

    Args:
        mse             : Mean Squared Error (non-negative float).
        max_pixel_value : Maximum channel value for the bit depth.
                          Default 255 for 8-bit images.

    Returns:
        PSNR in decibels (dB), or float("inf") for identical images.

    Raises:
        ValueError : If mse < 0 or max_pixel_value <= 0.
    """
    if not isinstance(mse, (int, float)) or math.isnan(mse):
        raise ValueError(f"mse must be a numeric value; got {mse!r}.")
    if mse < 0:
        raise ValueError(f"mse must be non-negative; got {mse}.")
    if not isinstance(max_pixel_value, (int, float)) or max_pixel_value <= 0:
        raise ValueError(
            f"max_pixel_value must be a positive number; got {max_pixel_value!r}."
        )

    if mse == 0.0:
        return float("inf")

    return 10.0 * math.log10((max_pixel_value ** 2) / mse)


# ─── Combined analysis ────────────────────────────────────────────────────────

def analyze_image_difference(
    original: Image.Image,
    stego: Image.Image,
    max_pixel_value: int = 255,
) -> dict:
    """
    Compute MSE, PSNR, and basic geometry for the original vs stego pair.

    Returns a JSON-serializable dict suitable for the Flask UI.

    Args:
        original        : The cover image.
        stego           : The stego image.
        max_pixel_value : Maximum pixel channel value (255 for 8-bit).

    Returns:
        {
            "mse":          float,   e.g. 0.003333…
            "psnr":         float,   e.g. 72.9 or math.inf
            "psnr_display": str,     e.g. "72.90 dB" or "∞ (identical images)"
            "width":        int,
            "height":       int,
            "channels":     3,       always 3 (after RGB conversion)
        }

    Raises:
        AnalysisError : If dimensions differ.
    """
    mse  = calculate_mse(original, stego)
    psnr = calculate_psnr(mse, max_pixel_value)

    width, height = original.convert("RGB").size

    if math.isinf(psnr):
        psnr_display = "∞ (identical images)"
    else:
        psnr_display = f"{psnr:.2f} dB"

    return {
        "mse":          round(mse, 8),
        "psnr":         psnr,
        "psnr_display": psnr_display,
        "width":        width,
        "height":       height,
        "channels":     3,
    }


# ─── Capacity analysis ───────────────────────────────────────────────────────

def get_capacity_info(image: Image.Image) -> dict:
    """
    Return detailed LSB capacity metrics for an image.

    Delegates to steganography.lsb.calculate_capacity() — does NOT
    duplicate the capacity formula (width × height × 3 ÷ 8 − 4).

    Args:
        image : Any Pillow Image.  Converted to RGB for calculation.

    Returns:
        {
            "width":            int,
            "height":           int,
            "channels":         3,
            "total_pixels":     int,
            "embedding_bits":   int,   W × H × 3
            "total_bytes":      int,   embedding_bits // 8
            "header_bytes":     4,
            "payload_capacity": int,   usable payload bytes (after 4-byte header)
        }
    """
    img_rgb = image.convert("RGB")
    width, height = img_rgb.size

    embedding_bits  = width * height * 3
    total_bytes     = embedding_bits // 8
    payload_cap     = calculate_capacity(img_rgb)   # delegates — no duplication

    return {
        "width":            width,
        "height":           height,
        "channels":         3,
        "total_pixels":     width * height,
        "embedding_bits":   embedding_bits,
        "total_bytes":      total_bytes,
        "header_bytes":     4,
        "payload_capacity": payload_cap,
    }


# ─── Payload utilization ──────────────────────────────────────────────────────

def calculate_payload_utilization(payload_size: int, capacity: int) -> float:
    """
    Calculate what percentage of the image's LSB capacity is occupied
    by the embedded payload.

    Formula:
        utilization (%) = (payload_size / capacity) × 100

    Args:
        payload_size : Number of serialized payload bytes embedded.
        capacity     : Total payload capacity returned by calculate_capacity().

    Returns:
        Percentage float.  Returns 0.0 if capacity == 0 (avoids ZeroDivisionError).
        Values above 100.0 indicate the payload exceeds capacity (shouldn't happen
        in normal operation, but the function does not raise for this case).

    Raises:
        ValueError : If payload_size < 0 or capacity < 0.
    """
    if not isinstance(payload_size, int) or payload_size < 0:
        raise ValueError(
            f"payload_size must be a non-negative integer; got {payload_size!r}."
        )
    if not isinstance(capacity, int) or capacity < 0:
        raise ValueError(
            f"capacity must be a non-negative integer; got {capacity!r}."
        )

    if capacity == 0:
        return 0.0

    return (payload_size / capacity) * 100.0
