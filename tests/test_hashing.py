"""
tests/test_hashing.py
─────────────────────
Automated tests for the crypto/hashing.py module.

Tests verify:
  1.  SHA-256 of empty bytes matches the known standard digest.
  2.  SHA-256 of b"Hello CNS Lab" matches hashlib reference.
  3.  sha256_bytes()  returns exactly 32 bytes.
  4.  sha256_hex()    returns exactly 64 hexadecimal characters.
  5.  Raw digest converted to hex matches sha256_hex() output.
  6.  Same input always produces the same hash (determinism).
  7.  One-byte change in input produces a different hash (avalanche).
  8.  Different inputs produce different hashes.
  9.  UTF-8 encoded Unicode can be hashed correctly.
  10. sha256_components() matches direct hashlib of salt + nonce + ciphertext.
  11. Different component values produce different hashes.
  12. Invalid input types are rejected with TypeError.

Run with:
    pytest tests/test_hashing.py -v

Combined with Phase 2:
    pytest tests/test_crypto.py tests/test_hashing.py -v
"""

import hashlib
import os

import pytest

from crypto.hashing import (
    sha256_bytes,
    sha256_hex,
    sha256_components,
    sha256_components_hex,
)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1 — SHA-256 of empty bytes matches the known standard digest
# ─────────────────────────────────────────────────────────────────────────────

# The SHA-256 digest of an empty byte string is a well-known constant defined
# in the SHA-256 specification.  This test anchors the implementation to the
# standard.
KNOWN_EMPTY_SHA256_HEX = (
    "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855"
)

def test_sha256_empty_bytes_known_digest():
    """
    SHA-256("") is a well-known value from the standard.
    Any correct SHA-256 implementation must produce this exact result.
    """
    result = sha256_hex(b"")
    assert result == KNOWN_EMPTY_SHA256_HEX, (
        f"Expected known empty-input digest, got: {result}"
    )


def test_sha256_empty_bytes_raw_matches_known():
    """
    sha256_bytes(b"") should equal the bytes form of the known hex digest.
    """
    expected_bytes = bytes.fromhex(KNOWN_EMPTY_SHA256_HEX)
    assert sha256_bytes(b"") == expected_bytes


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2 — SHA-256 of b"Hello CNS Lab" matches hashlib reference
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_hello_cns_lab_matches_hashlib():
    """
    sha256_hex(b"Hello CNS Lab") must produce the same result as calling
    hashlib.sha256(b"Hello CNS Lab").hexdigest() directly.

    This cross-checks our wrapper against Python's standard library to
    ensure we are not accidentally transforming the input before hashing.
    """
    data     = b"Hello CNS Lab"
    expected = hashlib.sha256(data).hexdigest()
    result   = sha256_hex(data)

    assert result == expected, (
        f"Expected hashlib reference {expected!r}, got {result!r}"
    )


def test_sha256_bytes_hello_cns_lab_matches_hashlib():
    """Same cross-check for sha256_bytes()."""
    data     = b"Hello CNS Lab"
    expected = hashlib.sha256(data).digest()
    assert sha256_bytes(data) == expected


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3 — sha256_bytes() returns exactly 32 bytes
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_bytes_output_length():
    """
    SHA-256 always produces a 256-bit (32-byte) digest regardless of
    input length.  Verify for a range of input sizes.
    """
    test_inputs = [
        b"",
        b"a",
        b"Hello CNS Lab",
        b"x" * 1000,
        os.urandom(256),
    ]
    for data in test_inputs:
        result = sha256_bytes(data)
        assert len(result) == 32, (
            f"Expected 32-byte digest for input of length {len(data)}, "
            f"got {len(result)}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 4 — sha256_hex() returns exactly 64 hexadecimal characters
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_hex_output_length_and_format():
    """
    A SHA-256 hex digest is always exactly 64 lowercase hex characters:
    32 bytes × 2 hex digits per byte = 64 characters.
    """
    test_inputs = [b"", b"abc", b"Hello CNS Lab", os.urandom(64)]
    hex_chars   = set("0123456789abcdef")

    for data in test_inputs:
        result = sha256_hex(data)
        assert len(result) == 64, (
            f"Expected 64-char hex string, got length {len(result)}"
        )
        assert all(c in hex_chars for c in result), (
            f"Hex digest contains non-hex characters: {result!r}"
        )
        assert result == result.lower(), "Hex digest must be lowercase"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 5 — Raw digest converted to hex matches sha256_hex()
# ─────────────────────────────────────────────────────────────────────────────

def test_bytes_to_hex_consistency():
    """
    sha256_bytes(data).hex() must equal sha256_hex(data).
    Both functions must agree on the same underlying digest.
    """
    test_inputs = [b"", b"Hello CNS Lab", b"consistency check", os.urandom(32)]

    for data in test_inputs:
        raw = sha256_bytes(data)
        hex_from_raw = raw.hex()
        hex_direct   = sha256_hex(data)

        assert hex_from_raw == hex_direct, (
            f"Inconsistency for input {data!r}: "
            f"bytes.hex()={hex_from_raw!r}, sha256_hex()={hex_direct!r}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 6 — Same input always produces the same hash (determinism)
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_is_deterministic():
    """
    SHA-256 is a deterministic function: the same input must always produce
    the same output.  Running it 10 times must yield the same digest every time.
    """
    data = b"CNS Lab determinism test"
    expected = sha256_hex(data)

    for _ in range(9):
        assert sha256_hex(data) == expected, (
            "SHA-256 is not deterministic — got different digest for same input"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 7 — One-byte change in input produces a different hash (avalanche effect)
# ─────────────────────────────────────────────────────────────────────────────

def test_single_byte_change_changes_digest():
    """
    SHA-256 exhibits the avalanche effect: changing even a single bit in the
    input should change approximately half of the output bits.  This test
    verifies the property by checking that the full digest differs after
    changing one byte.
    """
    original = b"Hello CNS Lab"

    # Flip the last byte (b'b' XOR 0xFF → a different byte).
    modified = original[:-1] + bytes([original[-1] ^ 0xFF])

    digest_original = sha256_hex(original)
    digest_modified = sha256_hex(modified)

    assert digest_original != digest_modified, (
        "Single-byte change must produce a different SHA-256 digest"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 8 — Different inputs produce different hashes
# ─────────────────────────────────────────────────────────────────────────────

def test_different_inputs_different_hashes():
    """
    Verify that a sample of clearly different inputs produce different digests.

    NOTE: SHA-256 is collision-resistant in practice, but not theoretically
    perfect — the test uses obviously distinct inputs where a collision is
    astronomically unlikely.
    """
    inputs = [
        b"message one",
        b"message two",
        b"message three",
        b"",
        b"\x00",
        b"\xff",
        b"Hello CNS Lab",
    ]
    digests = [sha256_hex(d) for d in inputs]

    # All digests in the list must be unique.
    assert len(digests) == len(set(digests)), (
        "Two different inputs produced the same SHA-256 digest (unexpected collision)"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 9 — UTF-8 encoded Unicode can be hashed correctly
# ─────────────────────────────────────────────────────────────────────────────

def test_utf8_unicode_hashing():
    """
    Multi-byte UTF-8 sequences (emoji, Devanagari) must be hashable without
    errors.  The caller is responsible for encoding strings to bytes before
    calling sha256_bytes() / sha256_hex() — the module does not silently
    encode.

    This test shows the intended usage pattern for string data.
    """
    text = "Hello 🔐 CNS"
    data = text.encode("utf-8")

    # Must not raise.
    result_bytes = sha256_bytes(data)
    result_hex   = sha256_hex(data)

    # Cross-check against hashlib reference.
    expected_hex = hashlib.sha256(data).hexdigest()

    assert result_hex == expected_hex
    assert len(result_bytes) == 32
    assert len(result_hex)   == 64


# ─────────────────────────────────────────────────────────────────────────────
# TEST 10 — sha256_components() matches direct hashlib of salt ‖ nonce ‖ ct
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_components_matches_direct_hashlib():
    """
    sha256_components(salt, nonce, ciphertext) must produce the same digest as:

        hashlib.sha256(salt + nonce + ciphertext).digest()

    This confirms that the incremental .update() approach is semantically
    identical to hashing the concatenated byte string.
    """
    salt       = os.urandom(32)
    nonce      = os.urandom(12)
    ciphertext = os.urandom(48)  # 32-byte payload + 16-byte GCM tag

    # Reference: direct concatenation.
    expected = hashlib.sha256(salt + nonce + ciphertext).digest()

    # Our function using incremental updates.
    result = sha256_components(salt, nonce, ciphertext)

    assert result == expected, (
        "sha256_components() output does not match direct hashlib reference"
    )


def test_sha256_components_hex_matches_direct_hashlib():
    """Same check for sha256_components_hex()."""
    salt       = os.urandom(32)
    nonce      = os.urandom(12)
    ciphertext = os.urandom(48)

    expected = hashlib.sha256(salt + nonce + ciphertext).hexdigest()
    result   = sha256_components_hex(salt, nonce, ciphertext)

    assert result == expected


# ─────────────────────────────────────────────────────────────────────────────
# TEST 11 — Different component values produce different hashes
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_components_different_values_different_hashes():
    """
    Changing any individual component (salt, nonce, or ciphertext) must
    produce a different digest.  This confirms the integrity guarantee:
    any modification to the payload bytes will be detectable.
    """
    salt       = os.urandom(32)
    nonce      = os.urandom(12)
    ciphertext = os.urandom(48)

    original_digest = sha256_components(salt, nonce, ciphertext)

    # Change the salt only.
    different_salt = os.urandom(32)
    assert different_salt != salt  # sanity: random salts should differ
    assert sha256_components(different_salt, nonce, ciphertext) != original_digest

    # Change the nonce only.
    different_nonce = os.urandom(12)
    assert different_nonce != nonce
    assert sha256_components(salt, different_nonce, ciphertext) != original_digest

    # Change the ciphertext only.
    tampered_ct = bytearray(ciphertext)
    tampered_ct[0] ^= 0xFF                     # flip first byte
    assert sha256_components(salt, nonce, bytes(tampered_ct)) != original_digest


def test_sha256_components_is_deterministic():
    """
    sha256_components() with the same inputs must always produce the same digest.
    """
    salt       = os.urandom(32)
    nonce      = os.urandom(12)
    ciphertext = os.urandom(48)

    first = sha256_components(salt, nonce, ciphertext)
    for _ in range(4):
        assert sha256_components(salt, nonce, ciphertext) == first, (
            "sha256_components() is not deterministic"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 12 — Invalid input types are rejected with TypeError
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_bytes_rejects_string():
    """sha256_bytes() must reject plain strings — caller must encode first."""
    with pytest.raises(TypeError):
        sha256_bytes("not bytes")  # type: ignore[arg-type]


def test_sha256_bytes_rejects_int():
    with pytest.raises(TypeError):
        sha256_bytes(12345)  # type: ignore[arg-type]


def test_sha256_bytes_rejects_none():
    with pytest.raises(TypeError):
        sha256_bytes(None)  # type: ignore[arg-type]


def test_sha256_hex_rejects_string():
    with pytest.raises(TypeError):
        sha256_hex("not bytes")  # type: ignore[arg-type]


def test_sha256_components_rejects_string_salt():
    """sha256_components() must reject non-bytes in any argument."""
    nonce      = os.urandom(12)
    ciphertext = os.urandom(48)
    with pytest.raises(TypeError):
        sha256_components("bad salt", nonce, ciphertext)  # type: ignore[arg-type]


def test_sha256_components_rejects_string_nonce():
    salt       = os.urandom(32)
    ciphertext = os.urandom(48)
    with pytest.raises(TypeError):
        sha256_components(salt, "bad nonce", ciphertext)  # type: ignore[arg-type]


def test_sha256_components_rejects_string_ciphertext():
    salt  = os.urandom(32)
    nonce = os.urandom(12)
    with pytest.raises(TypeError):
        sha256_components(salt, nonce, "bad ct")  # type: ignore[arg-type]


def test_sha256_components_rejects_none_arguments():
    salt  = os.urandom(32)
    nonce = os.urandom(12)
    ct    = os.urandom(48)
    with pytest.raises(TypeError):
        sha256_components(None, nonce, ct)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        sha256_components(salt, None, ct)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        sha256_components(salt, nonce, None)  # type: ignore[arg-type]


# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONAL — bytearray is accepted (bytes-like)
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_bytes_accepts_bytearray():
    """
    bytearray is a valid bytes-like object and should be accepted.
    This matters because some image processing libraries return bytearray.
    """
    data = bytearray(b"Hello CNS Lab")
    result = sha256_bytes(data)
    assert len(result) == 32
    assert result == hashlib.sha256(data).digest()


# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONAL — Confirm no reversal function exists in the module
# ─────────────────────────────────────────────────────────────────────────────

def test_no_reversal_function_in_module():
    """
    SHA-256 is a one-way function.  Verify that hashing.py does not expose
    any function whose name suggests reversal.  This is an academic correctness
    guard that also protects against accidentally importing a wrong module.
    """
    import crypto.hashing as hashing_module

    forbidden_names = [
        "decrypt_hash",
        "reverse_hash",
        "decode_hash",
        "invert_hash",
        "unhash",
    ]
    for name in forbidden_names:
        assert not hasattr(hashing_module, name), (
            f"Module must not expose a reversal function named '{name}'"
        )
