"""
tests/test_steganography.py
────────────────────────────
Automated tests for steganography/lsb.py.

Tests cover:
  1.  Capacity calculation (100×100 RGB — exact arithmetic).
  2.  Embed/extract simple payload (b"Hello CNS Lab").
  3.  Empty payload (b"") round trip.
  4.  Binary payload (bytes 0–255) round trip.
  5.  Large payload (close to capacity) round trip.
  6.  Payload exactly at maximum capacity — succeeds.
  7.  Payload one byte larger than capacity — CapacityError.
  8.  RGB image support.
  9.  RGBA image support + output is RGB.
  10. Image dimensions unchanged after embedding.
  11. Original image object is not modified.
  12. Only LSBs are modified (higher bits unchanged).
  13. Extraction from image with no payload — ExtractionError.
  14. Corrupted/truncated payload — ExtractionError.
  15. Invalid input types — appropriate exceptions.
  16. Deterministic: same payload + same image → same stego image.

Run with:
    pytest tests/test_steganography.py -v

Combined with all previous phases:
    pytest tests/test_crypto.py tests/test_hashing.py
           tests/test_payload.py tests/test_steganography.py -v
"""

import struct

import numpy as np
import pytest
from PIL import Image

from steganography.lsb import (
    calculate_capacity,
    embed_payload,
    extract_payload,
    CapacityError,
    ExtractionError,
    SteganographyError,
    HEADER_BYTES,
)


# ─── Image factory helpers ────────────────────────────────────────────────────

def make_rgb_image(width: int, height: int, color: tuple = (100, 150, 200)) -> Image.Image:
    """Create a solid-colour RGB image of the given dimensions."""
    return Image.new("RGB", (width, height), color)


def make_rgba_image(width: int, height: int,
                    color: tuple = (100, 150, 200, 128)) -> Image.Image:
    """Create a solid-colour RGBA image of the given dimensions."""
    return Image.new("RGBA", (width, height), color)


def make_random_rgb_image(width: int, height: int, seed: int = 42) -> Image.Image:
    """Create an RGB image with random pixel values (reproducible with seed)."""
    rng  = np.random.default_rng(seed)
    data = rng.integers(0, 256, size=(height, width, 3), dtype=np.uint8)
    return Image.fromarray(data, mode="RGB")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1 — Capacity calculation (100 × 100 RGB)
# ─────────────────────────────────────────────────────────────────────────────

def test_capacity_100x100_rgb_exact():
    """
    100 × 100 RGB image:
        total bits  = 100 × 100 × 3 = 30 000
        total bytes = 30 000 // 8   = 3 750
        payload cap = 3 750 − 4     = 3 746   (subtract 4-byte header)
    """
    image    = make_rgb_image(100, 100)
    capacity = calculate_capacity(image)
    assert capacity == 3_746, f"Expected 3 746, got {capacity}"


def test_capacity_formula_various_sizes():
    """
    Verify capacity formula for several image sizes.
    capacity = (W × H × 3) // 8  −  4
    """
    test_cases = [
        (100,  100,  3_746),
        (200,  200, 14_996),
        (640,  480, 115_196),
        (1920, 1080, 777_596),
    ]
    for w, h, expected in test_cases:
        img      = make_rgb_image(w, h)
        capacity = calculate_capacity(img)
        assert capacity == expected, (
            f"{w}×{h}: expected {expected}, got {capacity}"
        )


def test_capacity_rgba_same_as_rgb():
    """
    RGBA image capacity should equal the equivalent RGB image capacity
    because the alpha channel is discarded on conversion.
    """
    rgb  = make_rgb_image(100, 100)
    rgba = make_rgba_image(100, 100)
    assert calculate_capacity(rgb) == calculate_capacity(rgba)


def test_capacity_tiny_image_is_zero():
    """An image too small to hold the 4-byte header has capacity 0."""
    # 1×1 RGB → 3 channels → 0 bytes → capacity = max(0, 0-4) = 0
    tiny = make_rgb_image(1, 1)
    assert calculate_capacity(tiny) == 0


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2 — Embed / extract simple ASCII payload
# ─────────────────────────────────────────────────────────────────────────────

def test_embed_extract_simple_payload():
    """
    Embed b"Hello CNS Lab" into a 100×100 RGB image and extract it.
    The extracted bytes must be byte-identical to the original.
    """
    image   = make_rgb_image(100, 100)
    payload = b"Hello CNS Lab"

    stego     = embed_payload(image, payload)
    extracted = extract_payload(stego)

    assert extracted == payload


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3 — Empty payload round trip
# ─────────────────────────────────────────────────────────────────────────────

def test_empty_payload_round_trip():
    """
    An empty payload (b"") must be embeddable and extractable.
    The 4-byte header records length 0; extraction returns b"".
    """
    image = make_rgb_image(100, 100)

    stego     = embed_payload(image, b"")
    extracted = extract_payload(stego)

    assert extracted == b""


def test_empty_payload_header_encodes_zero():
    """
    After embedding b"", the first 32 channel LSBs must encode the value 0
    (the header representing payload length 0).
    """
    image = make_rgb_image(100, 100)
    stego = embed_payload(image, b"")

    channels = np.array(stego).flatten()
    header_bits  = (channels[:32] & 1).astype(np.uint8)
    header_bytes = np.packbits(header_bits).tobytes()
    length       = struct.unpack(">I", header_bytes)[0]

    assert length == 0, f"Header should encode 0 for empty payload, got {length}"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 4 — Binary payload round trip
# ─────────────────────────────────────────────────────────────────────────────

def test_binary_payload_round_trip():
    """
    Arbitrary binary bytes (including 0x00 and 0xFF) must survive
    embed → extract unchanged.
    """
    image   = make_rgb_image(100, 100)
    payload = bytes([0, 1, 2, 3, 127, 128, 254, 255])

    stego     = embed_payload(image, payload)
    extracted = extract_payload(stego)

    assert extracted == payload


def test_all_byte_values_round_trip():
    """
    All 256 possible byte values (0–255) in a single payload must
    round-trip correctly.
    """
    image   = make_rgb_image(200, 200)
    payload = bytes(range(256))

    stego     = embed_payload(image, payload)
    extracted = extract_payload(stego)

    assert extracted == payload


def test_random_binary_payload_round_trip():
    """Random binary payload must survive embed → extract unchanged."""
    rng     = np.random.default_rng(0)
    image   = make_random_rgb_image(200, 200, seed=1)
    payload = rng.integers(0, 256, size=500, dtype=np.uint8).tobytes()

    stego     = embed_payload(image, payload)
    extracted = extract_payload(stego)

    assert extracted == payload


# ─────────────────────────────────────────────────────────────────────────────
# TEST 5 — Large payload (close to capacity)
# ─────────────────────────────────────────────────────────────────────────────

def test_large_payload_round_trip():
    """
    A payload close to (but not exceeding) the image capacity must
    embed and extract correctly.
    """
    image    = make_rgb_image(200, 200)
    capacity = calculate_capacity(image)

    # Use 90% of capacity to stay safely under the limit.
    target   = int(capacity * 0.9)
    payload  = bytes(range(256)) * (target // 256) + bytes(range(target % 256))

    stego     = embed_payload(image, payload)
    extracted = extract_payload(stego)

    assert extracted == payload


# ─────────────────────────────────────────────────────────────────────────────
# TEST 6 — Payload exactly at maximum capacity succeeds
# ─────────────────────────────────────────────────────────────────────────────

def test_payload_at_exact_capacity_succeeds():
    """
    A payload of exactly calculate_capacity() bytes must succeed.
    This verifies the boundary condition: capacity is truly the maximum.
    """
    image    = make_rgb_image(100, 100)
    capacity = calculate_capacity(image)
    payload  = bytes([0xAB] * capacity)   # fill with a known byte pattern

    stego     = embed_payload(image, payload)
    extracted = extract_payload(stego)

    assert extracted == payload
    assert len(extracted) == capacity


# ─────────────────────────────────────────────────────────────────────────────
# TEST 7 — Payload one byte larger than capacity raises CapacityError
# ─────────────────────────────────────────────────────────────────────────────

def test_payload_one_byte_over_capacity_rejected():
    """
    A payload of capacity + 1 bytes must raise CapacityError.
    This verifies the exact off-by-one boundary condition.
    """
    image    = make_rgb_image(100, 100)
    capacity = calculate_capacity(image)
    payload  = bytes(capacity + 1)    # one byte too large

    with pytest.raises(CapacityError):
        embed_payload(image, payload)


def test_payload_much_larger_than_capacity_rejected():
    """A vastly oversized payload must also raise CapacityError."""
    image = make_rgb_image(10, 10)
    with pytest.raises(CapacityError):
        embed_payload(image, bytes(1_000_000))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 8 — RGB image support
# ─────────────────────────────────────────────────────────────────────────────

def test_rgb_image_round_trip():
    """An RGB source image produces a working stego image."""
    image   = make_rgb_image(100, 100)
    payload = b"RGB test"

    assert image.mode == "RGB"

    stego     = embed_payload(image, payload)
    extracted = extract_payload(stego)

    assert extracted == payload


def test_rgb_stego_output_mode_is_rgb():
    """embed_payload() must always return an RGB image."""
    image = make_rgb_image(100, 100)
    stego = embed_payload(image, b"mode check")
    assert stego.mode == "RGB"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 9 — RGBA image support; output is RGB
# ─────────────────────────────────────────────────────────────────────────────

def test_rgba_image_round_trip():
    """An RGBA source image must produce a working stego image."""
    image   = make_rgba_image(100, 100)
    payload = b"RGBA test"

    assert image.mode == "RGBA"

    stego     = embed_payload(image, payload)
    extracted = extract_payload(stego)

    assert extracted == payload


def test_rgba_stego_output_is_rgb():
    """
    embed_payload() on an RGBA source must return an RGB (not RGBA) image.
    The alpha channel is discarded during the RGB conversion step.
    """
    rgba_image = make_rgba_image(100, 100)
    stego      = embed_payload(rgba_image, b"alpha discarded")

    assert stego.mode == "RGB", (
        f"Expected RGB output from RGBA source, got {stego.mode}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 10 — Image dimensions unchanged after embedding
# ─────────────────────────────────────────────────────────────────────────────

def test_image_dimensions_unchanged():
    """
    The stego image must have exactly the same width and height as the source.
    embed_payload() must not resize, crop, or pad the image.
    """
    original_size = (640, 480)
    image = make_rgb_image(*original_size)
    stego = embed_payload(image, b"dimension check")

    assert stego.size == original_size, (
        f"Expected size {original_size}, got {stego.size}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 11 — Original image object is not modified
# ─────────────────────────────────────────────────────────────────────────────

def test_original_image_not_modified():
    """
    embed_payload() must return a NEW image and leave the source unchanged.
    This protects callers who hold a reference to the original image.
    """
    image = make_random_rgb_image(100, 100, seed=99)

    # Snapshot the original pixel data before embedding.
    original_array = np.array(image.copy())

    stego = embed_payload(image, b"original preserved")

    # Pixel data of the source image object must be unchanged.
    after_array = np.array(image)
    assert np.array_equal(original_array, after_array), (
        "embed_payload() modified the source image pixel data"
    )


def test_stego_is_different_from_original():
    """
    The stego image should differ from the original (at least the LSBs of
    channels carrying payload bits must have changed).
    """
    image   = make_random_rgb_image(100, 100, seed=7)
    payload = b"changed"

    stego = embed_payload(image, payload)

    orig_array  = np.array(image.convert("RGB"))
    stego_array = np.array(stego)

    assert not np.array_equal(orig_array, stego_array), (
        "Stego image is byte-identical to the original — payload was not embedded"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 12 — Only LSBs are modified (higher bits are unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def test_only_lsbs_are_modified():
    """
    For every RGB channel in the stego image:
        abs(original_value − stego_value) ≤ 1

    AND:
        (original_value & 0xFE) == (stego_value & 0xFE)

    The second assertion is stronger: it confirms that only bit 0 changed.
    """
    image   = make_random_rgb_image(100, 100, seed=5)
    payload = b"lsb check " * 10

    stego = embed_payload(image, payload)

    orig_array  = np.array(image.convert("RGB")).astype(np.int16)
    stego_array = np.array(stego).astype(np.int16)

    # Absolute difference must not exceed 1 per channel.
    diff = np.abs(orig_array - stego_array)
    assert np.all(diff <= 1), (
        f"Some channels changed by more than 1 bit. Max diff: {diff.max()}"
    )

    # Upper 7 bits (bits 7–1) must be identical.
    orig_high  = np.array(image.convert("RGB")) & np.uint8(0xFE)
    stego_high = np.array(stego) & np.uint8(0xFE)
    assert np.array_equal(orig_high, stego_high), (
        "Higher bits (bits 7–1) were modified — only bit 0 should change"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 13 — Extraction from image with no valid payload
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_from_all_white_image_fails_safely():
    """
    An all-white image (channel values = 255 = 0b11111111, LSB = 1) will
    produce a 4-byte header of 0xFFFFFFFF = 4 294 967 295.
    This vastly exceeds any reasonable capacity → ExtractionError.
    """
    white_image = Image.new("RGB", (50, 50), (255, 255, 255))

    with pytest.raises(ExtractionError):
        extract_payload(white_image)


def test_extract_from_all_black_image_returns_empty():
    """
    An all-black image (channel values = 0 = 0b00000000, LSB = 0) will
    produce a 4-byte header of 0x00000000 = 0.
    This is a valid payload_length = 0 → return b"".
    """
    black_image = Image.new("RGB", (50, 50), (0, 0, 0))
    result = extract_payload(black_image)
    assert result == b""


def test_extract_from_random_image_raises_or_returns():
    """
    A random image with no embedded payload must either:
      (a) raise ExtractionError (most likely — header length > capacity), or
      (b) return a short b"" or some bytes that happen to pass validation.
    It must NOT crash with an unhandled exception.
    """
    random_image = make_random_rgb_image(30, 30, seed=12345)

    try:
        result = extract_payload(random_image)
        assert isinstance(result, bytes)  # (b) — unexpected but valid
    except ExtractionError:
        pass  # (a) — expected behaviour


# ─────────────────────────────────────────────────────────────────────────────
# TEST 14 — Corrupted payload / header claims larger payload than available
# ─────────────────────────────────────────────────────────────────────────────

def test_corrupted_header_raises_extraction_error():
    """
    Manually overwrite the embedded header to claim a payload length that
    exceeds the image capacity.  extract_payload() must raise ExtractionError
    without crashing or allocating huge memory.
    """
    image   = make_rgb_image(100, 100)
    payload = b"short"
    stego   = embed_payload(image, payload)

    # Tamper: set the first 32 channel LSBs to represent 0xFFFFFFFF.
    stego_array = np.array(stego, dtype=np.uint8)
    flat        = stego_array.flatten().copy()

    # Encode the value 4294967295 (MAX_UINT32) as 32 bits MSB-first.
    fake_length_bits = np.unpackbits(
        np.frombuffer(struct.pack(">I", 0xFFFFFFFF), dtype=np.uint8)
    )
    flat[:32] = (flat[:32] & np.uint8(0xFE)) | fake_length_bits

    tampered_array = flat.reshape(stego_array.shape)
    tampered_image = Image.fromarray(tampered_array, mode="RGB")

    with pytest.raises(ExtractionError):
        extract_payload(tampered_image)


def test_header_claims_more_than_available_channel_data():
    """
    Set the header to a valid-looking but too-large value that passes the
    capacity check but would extend beyond the image's channel array.
    extract_payload() must handle this as an ExtractionError.
    """
    # Use a small image where we can tightly control the numbers.
    # 20×20 RGB → 1200 channels → 150 total bytes → capacity = 146 bytes
    image    = make_rgb_image(20, 20)
    capacity = calculate_capacity(image)

    # First embed something small to get a valid stego image.
    stego = embed_payload(image, b"x")

    # Now overwrite the header with capacity+1 (which fails the check).
    stego_array = np.array(stego, dtype=np.uint8)
    flat        = stego_array.flatten().copy()

    bad_length      = capacity + 1
    bad_length_bits = np.unpackbits(
        np.frombuffer(struct.pack(">I", bad_length), dtype=np.uint8)
    )
    flat[:32] = (flat[:32] & np.uint8(0xFE)) | bad_length_bits

    tampered = Image.fromarray(flat.reshape(stego_array.shape), mode="RGB")

    with pytest.raises(ExtractionError):
        extract_payload(tampered)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 15 — Invalid input types raise appropriate exceptions
# ─────────────────────────────────────────────────────────────────────────────

def test_embed_rejects_string_payload():
    """embed_payload() must reject a plain string payload."""
    image = make_rgb_image(100, 100)
    with pytest.raises(TypeError):
        embed_payload(image, "not bytes")  # type: ignore[arg-type]


def test_embed_rejects_int_payload():
    with pytest.raises(TypeError):
        embed_payload(make_rgb_image(100, 100), 42)  # type: ignore[arg-type]


def test_embed_rejects_none_payload():
    with pytest.raises(TypeError):
        embed_payload(make_rgb_image(100, 100), None)  # type: ignore[arg-type]


def test_embed_accepts_bytearray():
    """bytearray is a valid bytes-like type and must be accepted."""
    image   = make_rgb_image(100, 100)
    payload = bytearray(b"bytearray test")
    stego   = embed_payload(image, payload)
    assert extract_payload(stego) == bytes(payload)


def test_embed_tiny_image_raises_capacity_error():
    """An image too small to hold the 4-byte header raises CapacityError."""
    tiny = make_rgb_image(1, 1)   # 3 channels → 0 full bytes → capacity = 0
    with pytest.raises(CapacityError):
        embed_payload(tiny, b"any")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 16 — Deterministic: same payload + same image → same stego pixels
# ─────────────────────────────────────────────────────────────────────────────

def test_embedding_is_deterministic():
    """
    Embedding the same payload into the same source image must always produce
    the same output pixel values.  The algorithm contains no randomness —
    all randomness in the full pipeline comes from AES encryption (Phase 2),
    not from the LSB layer.
    """
    image   = make_rgb_image(100, 100, color=(128, 64, 32))
    payload = b"determinism test"

    stego1 = embed_payload(image, payload)
    stego2 = embed_payload(image, payload)

    assert np.array_equal(np.array(stego1), np.array(stego2)), (
        "embed_payload() produced different pixel values for identical inputs"
    )


# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONAL — Header encodes correct length
# ─────────────────────────────────────────────────────────────────────────────

def test_header_encodes_correct_length():
    """
    After embedding, the first 32 channel LSBs must encode exactly
    len(payload) as a big-endian unsigned 32-bit integer.
    """
    image   = make_rgb_image(100, 100)
    payload = b"header length check"

    stego       = embed_payload(image, payload)
    channels    = np.array(stego).flatten()
    header_bits = (channels[:32] & 1).astype(np.uint8)
    header_raw  = np.packbits(header_bits).tobytes()
    length      = struct.unpack(">I", header_raw)[0]

    assert length == len(payload), (
        f"Header encodes {length}, expected {len(payload)}"
    )


def test_header_is_big_endian():
    """
    Verify that the 4-byte header is big-endian by checking a payload
    whose length has a known byte representation.

    Length 256 = 0x00 0x00 0x01 0x00  (big-endian)
               = 0x00 0x01 0x00 0x00  (little-endian)

    The first extracted byte of the header should be 0x00 (not 0x01),
    confirming big-endian encoding.
    """
    image   = make_rgb_image(100, 100)
    payload = bytes(256)   # payload_length = 256 = 0x00000100

    stego       = embed_payload(image, payload)
    channels    = np.array(stego).flatten()
    header_bits = (channels[:32] & 1).astype(np.uint8)
    header_raw  = np.packbits(header_bits).tobytes()

    # Big-endian 256 = b'\x00\x00\x01\x00'
    assert header_raw == struct.pack(">I", 256), (
        f"Header is not big-endian: got {header_raw.hex()}"
    )


def test_lsb_module_has_no_crypto_imports():
    """
    The LSB module must not import any cryptographic modules.
    This enforces the architectural separation between steganography
    and cryptography.
    """
    import ast
    import pathlib

    source = pathlib.Path("steganography/lsb.py").read_text(encoding="utf-8")
    tree   = ast.parse(source)

    forbidden_modules = {"crypto", "encryption", "hashing", "Crypto",
                         "cryptography", "hashlib", "hmac"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top not in forbidden_modules, (
                    f"lsb.py must not import '{alias.name}' (crypto separation)"
                )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                assert top not in forbidden_modules, (
                    f"lsb.py must not import from '{node.module}'"
                )


# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONAL — Unicode payload (UTF-8 encoded) round trip
# ─────────────────────────────────────────────────────────────────────────────

def test_utf8_payload_round_trip():
    """
    UTF-8 encoded Unicode text must round-trip correctly through LSB
    embedding/extraction (the LSB layer treats it as raw bytes).
    """
    image   = make_rgb_image(200, 200)
    text    = "Hello 🔐 CNS — नमस्ते"
    payload = text.encode("utf-8")

    stego     = embed_payload(image, payload)
    extracted = extract_payload(stego)

    assert extracted == payload
    assert extracted.decode("utf-8") == text


# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONAL — Exception hierarchy
# ─────────────────────────────────────────────────────────────────────────────

def test_capacity_error_is_steganography_error():
    """CapacityError must be a subclass of SteganographyError."""
    assert issubclass(CapacityError, SteganographyError)


def test_extraction_error_is_steganography_error():
    """ExtractionError must be a subclass of SteganographyError."""
    assert issubclass(ExtractionError, SteganographyError)
