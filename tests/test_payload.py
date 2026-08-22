"""
tests/test_payload.py
─────────────────────
Automated tests for utils/payload.py.

Tests cover:
  1.  Build a valid payload.
  2.  Serialize valid payload.
  3.  Parse serialized payload.
  4.  Serialize → parse round trip preserves all values.
  5.  Base64 decode returns original salt.
  6.  Base64 decode returns original nonce.
  7.  Base64 decode returns original ciphertext.
  8.  SHA-256 digest round trip (hex → bytes → hex).
  9.  Canonical serialization is deterministic.
  10. Missing field rejected (each of the 8 required fields).
  11. Wrong version rejected.
  12. Wrong algorithm rejected.
  13. Wrong KDF rejected.
  14. Wrong iteration count rejected.
  15. Invalid Base64 salt rejected.
  16. Invalid Base64 nonce rejected.
  17. Invalid Base64 ciphertext rejected.
  18. Salt with incorrect decoded length rejected.
  19. Nonce with incorrect decoded length rejected.
  20. Ciphertext shorter than 16 bytes rejected.
  21. SHA-256 with incorrect length rejected.
  22. SHA-256 with non-hex characters rejected.
  23. JSON array instead of object rejected.
  24. Invalid UTF-8 rejected.
  25. Garbage bytes rejected.
  26. Extra unknown fields are silently ignored (documented policy).
  27. Full integration round trip: encrypt → hash → build → serialize
       → parse → decode → decrypt.

Run with:
    pytest tests/test_payload.py -v

Combined with all previous phases:
    pytest tests/test_crypto.py tests/test_hashing.py tests/test_payload.py -v
"""

import base64
import hashlib
import json
import os

import pytest

from crypto.encryption import encrypt_message, decrypt_message
from crypto.hashing import sha256_components
from utils.payload import (
    build_payload,
    serialize_payload,
    parse_payload,
    decode_payload_fields,
    PayloadError,
    PAYLOAD_VERSION,
    SALT_LENGTH,
    NONCE_LENGTH,
    MIN_CIPHERTEXT_BYTES,
)


# ─── Shared fixtures ─────────────────────────────────────────────────────────

def _make_encrypted_data():
    """Return a fresh encrypted_data dict from encrypt_message()."""
    return encrypt_message("Hello CNS Lab", "test1234")


def _make_sha256_digest(enc: dict) -> bytes:
    """Return the SHA-256 digest of salt ‖ nonce ‖ ciphertext."""
    return sha256_components(enc["salt"], enc["nonce"], enc["ciphertext"])


def _make_valid_payload() -> dict:
    """Build and return a valid payload dict."""
    enc    = _make_encrypted_data()
    digest = _make_sha256_digest(enc)
    return build_payload(enc, digest)


def _make_valid_serialized() -> bytes:
    """Return valid serialized payload bytes."""
    return serialize_payload(_make_valid_payload())


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1 — Build a valid payload
# ─────────────────────────────────────────────────────────────────────────────

def test_build_payload_returns_dict():
    """build_payload() must return a Python dict."""
    payload = _make_valid_payload()
    assert isinstance(payload, dict)


def test_build_payload_has_all_required_fields():
    """All 8 required schema fields must be present."""
    payload = _make_valid_payload()
    for field in ("version", "algorithm", "kdf", "iterations",
                  "salt", "nonce", "ciphertext", "sha256"):
        assert field in payload, f"Missing field: '{field}'"


def test_build_payload_metadata_values():
    """Metadata fields must contain the correct constant values."""
    payload = _make_valid_payload()
    assert payload["version"]    == PAYLOAD_VERSION
    assert payload["algorithm"]  == "AES-256-GCM"
    assert payload["kdf"]        == "PBKDF2-HMAC-SHA256"
    assert payload["iterations"] == 600_000


def test_build_payload_binary_fields_are_strings():
    """
    After build_payload(), the binary fields (salt, nonce, ciphertext) must
    be Base64 strings, not raw bytes — JSON cannot represent raw bytes.
    """
    payload = _make_valid_payload()
    for field in ("salt", "nonce", "ciphertext"):
        assert isinstance(payload[field], str), (
            f"Field '{field}' must be a string after build_payload()"
        )


def test_build_payload_sha256_is_64_char_hex():
    """The sha256 field must be a 64-character lowercase hex string."""
    payload = _make_valid_payload()
    sha256  = payload["sha256"]
    assert isinstance(sha256, str)
    assert len(sha256) == 64
    assert sha256 == sha256.lower()
    assert all(c in "0123456789abcdef" for c in sha256)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2 — Serialize valid payload
# ─────────────────────────────────────────────────────────────────────────────

def test_serialize_payload_returns_bytes():
    """serialize_payload() must return bytes."""
    result = _make_valid_serialized()
    assert isinstance(result, bytes)


def test_serialize_payload_is_valid_json():
    """The serialized output must be parseable JSON."""
    result   = _make_valid_serialized()
    parsed   = json.loads(result.decode("utf-8"))
    assert isinstance(parsed, dict)


def test_serialize_payload_is_compact():
    """
    Compact serialization must not contain spaces after ':' or ','.
    Pretty-printed JSON would waste embedding capacity in the image.
    """
    result = _make_valid_serialized()
    text   = result.decode("utf-8")
    assert ": " not in text, "Unexpected space after colon — use separators=(',',':')"
    assert ", " not in text, "Unexpected space after comma — use separators=(',',':')"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3 — Parse serialized payload
# ─────────────────────────────────────────────────────────────────────────────

def test_parse_payload_returns_dict():
    """parse_payload() on valid bytes must return a dict."""
    result = parse_payload(_make_valid_serialized())
    assert isinstance(result, dict)


def test_parse_payload_has_all_required_fields():
    """Parsed dict must contain all required fields."""
    parsed = parse_payload(_make_valid_serialized())
    for field in ("version", "algorithm", "kdf", "iterations",
                  "salt", "nonce", "ciphertext", "sha256"):
        assert field in parsed


# ─────────────────────────────────────────────────────────────────────────────
# TEST 4 — Serialize → parse round trip preserves all values
# ─────────────────────────────────────────────────────────────────────────────

def test_round_trip_preserves_all_fields():
    """
    serialize_payload() → parse_payload() must produce a dict that is
    value-equal to the original payload.
    """
    original = _make_valid_payload()
    parsed   = parse_payload(serialize_payload(original))

    for field in ("version", "algorithm", "kdf", "iterations",
                  "salt", "nonce", "ciphertext", "sha256"):
        assert parsed[field] == original[field], (
            f"Round trip changed field '{field}': "
            f"{original[field]!r} → {parsed[field]!r}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 5–7 — Base64 decode returns original binary values
# ─────────────────────────────────────────────────────────────────────────────

def test_decoded_salt_matches_original():
    """decode_payload_fields()['salt'] must equal the original salt bytes."""
    enc    = _make_encrypted_data()
    digest = _make_sha256_digest(enc)
    payload = build_payload(enc, digest)
    decoded = decode_payload_fields(payload)
    assert decoded["salt"] == enc["salt"]


def test_decoded_nonce_matches_original():
    """decode_payload_fields()['nonce'] must equal the original nonce bytes."""
    enc    = _make_encrypted_data()
    digest = _make_sha256_digest(enc)
    payload = build_payload(enc, digest)
    decoded = decode_payload_fields(payload)
    assert decoded["nonce"] == enc["nonce"]


def test_decoded_ciphertext_matches_original():
    """decode_payload_fields()['ciphertext'] must equal the original ciphertext bytes."""
    enc    = _make_encrypted_data()
    digest = _make_sha256_digest(enc)
    payload = build_payload(enc, digest)
    decoded = decode_payload_fields(payload)
    assert decoded["ciphertext"] == enc["ciphertext"]


# ─────────────────────────────────────────────────────────────────────────────
# TEST 8 — SHA-256 digest round trip
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_digest_round_trip():
    """
    The SHA-256 digest must survive:
        bytes → hex string (in payload) → bytes (after decode_payload_fields)
    and equal the original digest bytes.
    """
    enc    = _make_encrypted_data()
    digest = _make_sha256_digest(enc)
    payload = build_payload(enc, digest)
    decoded = decode_payload_fields(payload)

    assert decoded["sha256"] == digest, (
        "SHA-256 digest did not survive the base64/hex round trip"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 9 — Canonical serialization is deterministic
# ─────────────────────────────────────────────────────────────────────────────

def test_serialization_is_deterministic():
    """
    serialize_payload() called multiple times on the SAME payload dict must
    produce byte-for-byte identical output each time.
    sort_keys=True ensures field order is stable.
    """
    payload = _make_valid_payload()
    first   = serialize_payload(payload)
    for _ in range(4):
        assert serialize_payload(payload) == first, (
            "Serialization is not deterministic for the same input"
        )


def test_serialization_keys_are_sorted():
    """
    The JSON keys must appear in alphabetical order (sort_keys=True).
    This makes debugging easier and output predictable.
    """
    payload   = _make_valid_payload()
    text      = serialize_payload(payload).decode("utf-8")
    parsed    = json.loads(text)
    keys_json = list(json.loads(text).keys())
    keys_sorted = sorted(parsed.keys())
    assert keys_json == keys_sorted, (
        f"Keys are not alphabetically sorted: {keys_json}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 10 — Missing field rejected
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("missing_field", [
    "version", "algorithm", "kdf", "iterations",
    "salt", "nonce", "ciphertext", "sha256",
])
def test_missing_field_rejected(missing_field):
    """
    parse_payload() must raise PayloadError if any required field is absent.
    Tests all 8 required fields independently.
    """
    payload = _make_valid_payload()
    del payload[missing_field]

    serialized = json.dumps(payload).encode("utf-8")

    with pytest.raises(PayloadError, match=missing_field):
        parse_payload(serialized)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 11 — Wrong version rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_wrong_version_rejected():
    """parse_payload() must reject a payload with version != 1."""
    payload = _make_valid_payload()
    payload["version"] = 99
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 12 — Wrong algorithm rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_wrong_algorithm_rejected():
    """An unsupported algorithm string must be rejected — prevents substitution attacks."""
    payload = _make_valid_payload()
    payload["algorithm"] = "AES-128-CBC"
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


def test_algorithm_must_be_exact_string():
    """Algorithm field must exactly match the allowlist — not a substring."""
    payload = _make_valid_payload()
    payload["algorithm"] = "AES-256-GCM-EXTRA"
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 13 — Wrong KDF rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_wrong_kdf_rejected():
    """An unsupported KDF string must be rejected."""
    payload = _make_valid_payload()
    payload["kdf"] = "scrypt"
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 14 — Wrong iteration count rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_wrong_iteration_count_rejected():
    """A different iteration count must be rejected to prevent key mismatch."""
    payload = _make_valid_payload()
    payload["iterations"] = 100_000
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


def test_zero_iterations_rejected():
    payload = _make_valid_payload()
    payload["iterations"] = 0
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 15–17 — Invalid Base64 fields rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_invalid_base64_salt_rejected():
    """A salt field that is not valid Base64 must be rejected."""
    payload = _make_valid_payload()
    payload["salt"] = "!!!not_base64!!!"
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


def test_invalid_base64_nonce_rejected():
    payload = _make_valid_payload()
    payload["nonce"] = "not===valid==="
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


def test_invalid_base64_ciphertext_rejected():
    payload = _make_valid_payload()
    payload["ciphertext"] = "@@@bad_base64@@@"
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 18 — Salt with incorrect decoded length rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_salt_wrong_length_rejected():
    """
    A Base64-encoded salt that decodes to a length other than 32 bytes
    must be rejected — a wrong-length salt would silently produce a
    different AES key and cause decryption to fail later.
    """
    payload = _make_valid_payload()
    # Encode 16 bytes instead of 32.
    payload["salt"] = base64.b64encode(os.urandom(16)).decode("ascii")
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 19 — Nonce with incorrect decoded length rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_nonce_wrong_length_rejected():
    """A nonce that decodes to a length other than 12 bytes must be rejected."""
    payload = _make_valid_payload()
    payload["nonce"] = base64.b64encode(os.urandom(8)).decode("ascii")  # wrong: 8 not 12
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 20 — Ciphertext shorter than 16 bytes rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_ciphertext_too_short_rejected():
    """
    A ciphertext field that decodes to fewer than 16 bytes must be rejected.
    A valid AES-GCM ciphertext always contains at least the 16-byte auth tag.
    """
    payload = _make_valid_payload()
    payload["ciphertext"] = base64.b64encode(os.urandom(8)).decode("ascii")
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 21 — SHA-256 with incorrect length rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_wrong_length_rejected():
    """A sha256 field that is not exactly 64 characters must be rejected."""
    payload = _make_valid_payload()
    payload["sha256"] = "a" * 32   # 32 chars, not 64
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


def test_sha256_too_long_rejected():
    payload = _make_valid_payload()
    payload["sha256"] = "a" * 128
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 22 — SHA-256 with non-hex characters rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_non_hex_chars_rejected():
    """A sha256 field containing non-hex characters must be rejected."""
    payload = _make_valid_payload()
    payload["sha256"] = "g" * 64   # 'g' is not a hex character
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


def test_sha256_uppercase_hex_rejected():
    """
    The sha256 field must be lowercase hex.
    Uppercase hex would still decode correctly but we enforce lowercase
    for a canonical, deterministic format.
    """
    payload = _make_valid_payload()
    payload["sha256"] = payload["sha256"].upper()  # force uppercase
    with pytest.raises(PayloadError):
        parse_payload(json.dumps(payload).encode("utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# TEST 23 — JSON array instead of object rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_json_array_rejected():
    """The payload must be a JSON object, not an array."""
    array_bytes = json.dumps([1, 2, 3]).encode("utf-8")
    with pytest.raises(PayloadError):
        parse_payload(array_bytes)


def test_json_string_rejected():
    """The payload must be a JSON object, not a bare string."""
    with pytest.raises(PayloadError):
        parse_payload(b'"just a string"')


def test_json_number_rejected():
    """The payload must be a JSON object, not a number."""
    with pytest.raises(PayloadError):
        parse_payload(b"42")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 24 — Invalid UTF-8 rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_invalid_utf8_rejected():
    """Bytes that are not valid UTF-8 must be rejected before JSON parsing."""
    invalid_utf8 = b"\xff\xfe\xfd"
    with pytest.raises(PayloadError):
        parse_payload(invalid_utf8)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 25 — Garbage bytes rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_garbage_bytes_rejected():
    """Random binary data should be rejected gracefully as a PayloadError."""
    garbage = os.urandom(256)
    with pytest.raises(PayloadError):
        parse_payload(garbage)


def test_empty_bytes_rejected():
    """Empty input must raise PayloadError, not crash."""
    with pytest.raises(PayloadError):
        parse_payload(b"")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 26 — Extra unknown fields are silently ignored
# ─────────────────────────────────────────────────────────────────────────────

def test_extra_unknown_fields_are_ignored():
    """
    Schema policy: extra fields not defined in version-1 schema are silently
    ignored.  This is a deliberate forward-compatibility choice:
      • A future version-2 payload with additional metadata can still be
        partially handled by this parser without raising an error.
      • The allowlisted algorithm / KDF / version values still prevent
        algorithm-substitution attacks — only truly unknown extra keys pass.

    This behaviour is documented in parse_payload()'s docstring.
    """
    payload = _make_valid_payload()
    payload["extra_field"]  = "some value"
    payload["another_field"] = 12345

    serialized = json.dumps(payload).encode("utf-8")

    # Must NOT raise PayloadError.
    parsed = parse_payload(serialized)

    # Extra fields are carried through (not stripped by parse_payload).
    assert "extra_field"   in parsed
    assert "another_field" in parsed

    # Required fields are still intact.
    assert parsed["version"]   == PAYLOAD_VERSION
    assert parsed["algorithm"] == "AES-256-GCM"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 27 — Full integration round trip
# ─────────────────────────────────────────────────────────────────────────────

def test_full_integration_round_trip():
    """
    Complete pipeline integration test:

        encrypt_message()        (Phase 2)
              ↓
        sha256_components()      (Phase 3)
              ↓
        build_payload()          (Phase 4)
              ↓
        serialize_payload()
              ↓
        parse_payload()
              ↓
        decode_payload_fields()
              ↓
        decrypt_message()        (Phase 2)

    Verifies compatibility between all three phases end-to-end.
    """
    # ── Phase 2: Encrypt ──────────────────────────────────────────────────────
    original_message = "Hello CNS Lab"
    password         = "test1234"

    encrypted = encrypt_message(original_message, password)

    salt       = encrypted["salt"]
    nonce      = encrypted["nonce"]
    ciphertext = encrypted["ciphertext"]

    # ── Phase 3: Hash ────────────────────────────────────────────────────────
    digest = sha256_components(salt, nonce, ciphertext)
    assert len(digest) == 32

    # ── Phase 4: Build + Serialize ───────────────────────────────────────────
    payload    = build_payload(encrypted, digest)
    serialized = serialize_payload(payload)
    assert isinstance(serialized, bytes)

    # ── Phase 4: Parse + Decode ──────────────────────────────────────────────
    parsed  = parse_payload(serialized)
    decoded = decode_payload_fields(parsed)

    # Binary values must be byte-identical to originals.
    assert decoded["salt"]       == salt,       "Salt mismatch after round trip"
    assert decoded["nonce"]      == nonce,      "Nonce mismatch after round trip"
    assert decoded["ciphertext"] == ciphertext, "Ciphertext mismatch after round trip"
    assert decoded["sha256"]     == digest,     "SHA-256 digest mismatch after round trip"

    # Metadata must be preserved.
    assert decoded["version"]    == PAYLOAD_VERSION
    assert decoded["algorithm"]  == "AES-256-GCM"
    assert decoded["kdf"]        == "PBKDF2-HMAC-SHA256"
    assert decoded["iterations"] == 600_000

    # ── Phase 2: Decrypt ─────────────────────────────────────────────────────
    # The decoded dict is compatible with decrypt_message() which needs
    # salt, nonce, ciphertext, iterations as bytes/int.
    recovered = decrypt_message(decoded, password)
    assert recovered == original_message, (
        f"Decryption after full pipeline returned {recovered!r}; "
        f"expected {original_message!r}"
    )


def test_full_pipeline_wrong_password_still_fails():
    """
    After the full pipeline, passing the wrong password to decrypt_message()
    must still raise DecryptionError — the payload module must not weaken
    the cryptographic security.
    """
    from crypto.encryption import DecryptionError

    encrypted = encrypt_message("Secret", "correct_pass")
    digest    = sha256_components(
        encrypted["salt"], encrypted["nonce"], encrypted["ciphertext"]
    )
    payload    = build_payload(encrypted, digest)
    serialized = serialize_payload(payload)
    parsed     = parse_payload(serialized)
    decoded    = decode_payload_fields(parsed)

    with pytest.raises(DecryptionError):
        decrypt_message(decoded, "wrong_pass")


def test_build_payload_rejects_missing_encrypted_fields():
    """build_payload() must reject an encrypted_data dict missing required keys."""
    digest = os.urandom(32)
    for missing in ("salt", "nonce", "ciphertext", "iterations"):
        enc = _make_encrypted_data()
        del enc[missing]
        with pytest.raises(PayloadError):
            build_payload(enc, digest)


def test_build_payload_rejects_short_sha256_digest():
    """build_payload() must reject a sha256_digest that is not exactly 32 bytes."""
    enc = _make_encrypted_data()
    with pytest.raises(PayloadError):
        build_payload(enc, os.urandom(16))   # 16, not 32


def test_build_payload_rejects_non_bytes_digest():
    """build_payload() must reject a non-bytes sha256_digest argument."""
    enc = _make_encrypted_data()
    with pytest.raises(PayloadError):
        build_payload(enc, "not bytes")   # type: ignore[arg-type]
