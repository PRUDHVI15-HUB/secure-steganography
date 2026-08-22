"""
steganography/lsb.py
────────────────────
Spatial-domain LSB (Least Significant Bit) image steganography.

What this module does
──────────────────────
It hides arbitrary binary data inside the pixel channel values of a
Pillow Image by modifying only the least significant bit of each
Red, Green, and Blue channel.

What this module does NOT do
──────────────────────────────
• It does NOT encrypt data.
• It does NOT hash data.
• It does NOT know about AES, PBKDF2, SHA-256, JSON, or Base64.
• It does NOT understand the structure of the hidden bytes.

Its only job:

    bytes  →  embed_payload()  →  PNG image
    PNG image  →  extract_payload()  →  bytes

The cryptographic and payload layers are handled in crypto/ and utils/.

Algorithm overview
───────────────────
Embedding:
  1. Convert image to RGB (discards alpha channel if RGBA).
  2. Prepend a 4-byte big-endian length header to the payload:
         [4 bytes: payload_length] + [payload bytes]
  3. Unpack each byte to 8 bits (MSB first).
  4. Iterate through flattened RGB channel values.
  5. For each payload bit, clear the LSB of the channel then set it:
         new_value = (old_value & 0xFE) | bit
  6. Reshape the channel array back into an image and return.

Extraction:
  1. Convert image to RGB.
  2. Read the first 32 channel LSBs → reconstruct the 4-byte length.
  3. Validate the length against the image capacity (UNTRUSTED INPUT).
  4. Read the next (length × 8) channel LSBs → reconstruct payload bytes.
  5. Return raw bytes.

Capacity
─────────
Each RGB pixel contributes 3 bits (one per channel).

    total_bits   = width × height × 3
    total_bytes  = total_bits // 8
    payload_cap  = total_bytes − 4     ← 4 bytes reserved for length header

Example: 1920 × 1080 RGB image
    = 6,220,800 bits = 777,600 bytes total
    payload capacity = 777,596 bytes

Limitations (educational note)
────────────────────────────────
LSB steganography in the spatial domain is NOT resistant to:
  • JPEG compression (lossy — destroys LSB modifications)
  • Image resizing or rotation
  • Colour quantisation
  • Certain statistical steganalysis techniques (e.g. RS analysis, χ²)

This module is an educational demonstration of spatial-domain steganography
as part of a Cryptography and Network Security laboratory project.

Author : CNS Lab Project
"""

import struct
from typing import Union

import numpy as np
from PIL import Image


# ─── Constants ───────────────────────────────────────────────────────────────

# The payload length is encoded as a 4-byte big-endian unsigned integer
# at the start of the embedded bit stream.
HEADER_BYTES: int = 4
HEADER_BITS:  int = HEADER_BYTES * 8   # 32 bits

# Maximum value of the 4-byte unsigned header (2^32 - 1 = 4 294 967 295).
# We compare extracted length against actual image capacity, not this value.
MAX_UINT32: int = (2 ** 32) - 1


# ─── Custom exceptions ───────────────────────────────────────────────────────

class SteganographyError(Exception):
    """
    Base exception for all steganography-related errors.

    Subclass to distinguish capacity errors from extraction failures
    in the Flask layer.
    """


class CapacityError(SteganographyError):
    """
    Raised when the payload is too large for the given image.

    The Flask layer converts this into:
        "Message is too large for this image."
    """


class ExtractionError(SteganographyError):
    """
    Raised when extraction fails:
      • No valid payload header detected.
      • Claimed payload length exceeds image capacity.
      • Insufficient image data to complete extraction.

    The Flask layer converts this into:
        "No valid payload found in this image."
    """


# ─── Public API ──────────────────────────────────────────────────────────────

def calculate_capacity(image: Image.Image) -> int:
    """
    Calculate the maximum number of payload bytes that can be embedded
    in *image* using 1-LSB-per-channel RGB steganography.

    The first 4 bytes of embedding space are always reserved for the
    payload length header; the returned value is the remaining capacity
    available for actual payload data.

    Formula:
        total_bits  = width × height × 3
        total_bytes = total_bits // 8
        capacity    = total_bytes − 4   (subtract 4-byte header)

    Args:
        image : Any Pillow Image.  Converted to RGB for the calculation.

    Returns:
        Maximum payload bytes (0 if the image is too small to hold even
        the 4-byte header).

    Example (100 × 100 RGB):
        100 × 100 × 3 = 30 000 bits = 3 750 bytes total
        payload capacity = 3 750 − 4 = 3 746 bytes
    """
    img_rgb = image.convert("RGB")
    width, height = img_rgb.size
    total_bits  = width * height * 3
    total_bytes = total_bits // 8
    return max(0, total_bytes - HEADER_BYTES)


def embed_payload(image: Image.Image, payload: bytes) -> Image.Image:
    """
    Embed *payload* bytes into *image* using LSB steganography.

    The payload is preceded by a 4-byte big-endian unsigned integer that
    records the payload length.  Only the least significant bit of each
    RGB channel is modified.

    Args:
        image   : Source Pillow Image (RGB or RGBA; other modes converted).
        payload : Arbitrary binary data to hide.  May be empty (b"").

    Returns:
        A new Pillow RGB Image containing the hidden payload.
        The source *image* object is never modified.

    Raises:
        TypeError      : If *payload* is not bytes or bytearray.
        CapacityError  : If the payload (plus 4-byte header) exceeds the
                         image's LSB embedding capacity.

    Notes:
        • RGBA images are converted to RGB; the alpha channel is discarded.
        • Image dimensions, bit depth, and higher bits of each channel are
          preserved exactly.
        • Save the returned image as PNG (lossless) to preserve LSB data.
    """
    # ── Type validation ───────────────────────────────────────────────────────
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError(
            f"payload must be bytes or bytearray, got {type(payload).__name__!r}."
        )

    # ── Convert source image to RGB ───────────────────────────────────────────
    # Converting to RGB ensures a predictable 3-channel layout and discards
    # the alpha channel if the source is RGBA.
    img_rgb = image.convert("RGB")
    width, height = img_rgb.size

    # ── Check the image is large enough to hold the 4-byte header at all ─────
    total_channels = width * height * 3
    total_bytes    = total_channels // 8

    if total_bytes < HEADER_BYTES:
        raise CapacityError(
            f"Image ({width}×{height}) is too small to embed even the "
            f"{HEADER_BYTES}-byte length header. "
            f"Total embedding space: {total_bytes} byte(s)."
        )

    # ── Validate payload fits within capacity ─────────────────────────────────
    capacity = calculate_capacity(img_rgb)
    if len(payload) > capacity:
        raise CapacityError(
            f"Payload ({len(payload):,} bytes) exceeds image capacity "
            f"({capacity:,} bytes). Use a larger image or a shorter message."
        )

    # ── Build the data stream: [4-byte header] + [payload] ───────────────────
    header = struct.pack(">I", len(payload))   # big-endian unsigned 32-bit
    data   = header + bytes(payload)

    # ── Convert data bytes to a flat array of bits (MSB first per byte) ──────
    # np.unpackbits operates on uint8 arrays and unpacks each byte MSB-first.
    # Example:  b'\x05' → [0, 0, 0, 0, 0, 1, 0, 1]
    data_np  = np.frombuffer(data, dtype=np.uint8)
    bits     = np.unpackbits(data_np)          # shape: (len(data) * 8,)
    n_bits   = len(bits)

    # Sanity check: the bit count must fit in the available channel count.
    # (Guaranteed by the capacity check above, but verified for safety.)
    assert n_bits <= total_channels, (
        "Internal error: bit count exceeds channel count despite capacity check."
    )

    # ── Get channel values as a 1-D array ────────────────────────────────────
    img_array = np.array(img_rgb, dtype=np.uint8)  # shape: (H, W, 3)
    channels  = img_array.flatten().copy()          # copy → original untouched

    # ── Embed bits into LSBs ──────────────────────────────────────────────────
    # (channel & 0xFE) clears the LSB.
    # | bit  sets the LSB to the payload bit (0 or 1).
    channels[:n_bits] = (channels[:n_bits] & np.uint8(0xFE)) | bits

    # ── Reconstruct the stego image ───────────────────────────────────────────
    stego_array = channels.reshape(img_array.shape)
    return Image.fromarray(stego_array, mode="RGB")


def extract_payload(image: Image.Image) -> bytes:
    """
    Extract a payload previously embedded by embed_payload().

    Reads the 4-byte big-endian length header from the first 32 channel
    LSBs, validates the claimed length against the image capacity, then
    reads exactly that many bytes from the subsequent LSBs.

    Args:
        image : Pillow Image containing an embedded payload (RGB or RGBA).

    Returns:
        The raw payload bytes (identical to what was passed to embed_payload).
        Returns b"" if the embedded payload length was 0.

    Raises:
        ExtractionError : If the image is too small, the claimed payload
                          length exceeds the image capacity, or insufficient
                          data is available to complete extraction.

    Security note:
        The 4-byte length header is UNTRUSTED INPUT.  This function always
        validates the extracted length against calculate_capacity() before
        allocating any memory for the payload.  This prevents a crafted
        image from causing an out-of-memory condition.
    """
    # ── Convert to RGB for consistent 3-channel layout ────────────────────────
    img_rgb = image.convert("RGB")
    width, height = img_rgb.size

    # ── Ensure image is large enough to contain the 4-byte header ────────────
    total_channels = width * height * 3
    total_bytes    = total_channels // 8

    if total_bytes < HEADER_BYTES:
        raise ExtractionError(
            f"Image ({width}×{height}) is too small to contain a payload "
            f"header (minimum {HEADER_BYTES * 8} channels needed; "
            f"image has {total_channels})."
        )

    # ── Extract all channel values as a flat array ────────────────────────────
    img_array = np.array(img_rgb, dtype=np.uint8)
    channels  = img_array.flatten()

    # ── Read the first 32 LSBs → reconstruct the 4-byte payload length ───────
    header_bits  = (channels[:HEADER_BITS] & np.uint8(1)).astype(np.uint8)
    header_bytes = np.packbits(header_bits).tobytes()          # 4 bytes
    payload_length: int = struct.unpack(">I", header_bytes)[0]

    # ── Validate payload length BEFORE allocating memory ─────────────────────
    # This is the primary security check against crafted/malicious images.
    capacity = calculate_capacity(img_rgb)

    if payload_length > capacity:
        raise ExtractionError(
            f"Extracted payload length ({payload_length:,} bytes) exceeds "
            f"image capacity ({capacity:,} bytes). "
            f"This image likely contains no valid embedded payload."
        )

    # ── Handle zero-length payload ────────────────────────────────────────────
    if payload_length == 0:
        return b""

    # ── Read exactly payload_length × 8 additional LSBs ──────────────────────
    payload_start_bit = HEADER_BITS                    # bit index 32
    payload_end_bit   = HEADER_BITS + payload_length * 8

    # This should be guaranteed by the capacity check, but guard anyway.
    if payload_end_bit > total_channels:
        raise ExtractionError(
            f"Payload data extends beyond image boundaries. "
            f"The embedded data may be corrupted or truncated."
        )

    payload_bits  = (channels[payload_start_bit:payload_end_bit] & np.uint8(1)).astype(np.uint8)
    payload_bytes = np.packbits(payload_bits).tobytes()

    # np.packbits may pad the last group with zeros if the bit count is not a
    # multiple of 8.  Since payload_length * 8 IS always a multiple of 8, no
    # padding occurs — but we trim for safety.
    return payload_bytes[:payload_length]
