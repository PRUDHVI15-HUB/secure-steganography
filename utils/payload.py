"""
utils/payload.py
────────────────
Versioned payload container for the steganography pipeline.

Role in the full pipeline
──────────────────────────
This module sits between the cryptographic layer (Phase 2/3) and the
steganography layer (Phase 5).  Its only jobs are:

    BUILD    : combine AES-GCM output + SHA-256 digest into a single dict
    SERIALIZE: dict → compact deterministic JSON → UTF-8 bytes
    PARSE    : UTF-8 bytes → JSON → validated dict
    DECODE   : base64 fields back to raw bytes

It does NOT encrypt, decrypt, hash, or touch pixel data.

Why Base64?
───────────
JSON is a text format.  It cannot represent arbitrary binary bytes directly.
Converting binary data to its string representation (e.g. str(b'\\x00'))
would produce an undecodable string.  Base64 encodes each group of 3 bytes as
4 printable ASCII characters — a lossless, standard encoding that JSON handles
without issue.

    bytes
      ↓  base64.b64encode()
    base64 string  ←→  stored in JSON
      ↓  base64.b64decode()
    bytes  (original, identical)

Payload JSON schema  (version 1)
─────────────────────────────────
{
    "version"    : 1,
    "algorithm"  : "AES-256-GCM",
    "kdf"        : "PBKDF2-HMAC-SHA256",
    "iterations" : 600000,
    "salt"       : "<base64 — 32 bytes>",
    "nonce"      : "<base64 — 12 bytes>",
    "ciphertext" : "<base64 — encrypted message + 16-byte GCM auth tag>",
    "sha256"     : "<64-character lowercase hex — SHA-256 of salt‖nonce‖ciphertext>"
}

Security constraints
─────────────────────
• The password is NEVER stored in the payload.
• The derived AES key is NEVER stored in the payload.
• Algorithm and KDF names are validated against explicit allowlists.
• eval(), exec(), pickle are not used.
• Unknown extra JSON fields are silently ignored (forward-compatible design —
  a future version-2 payload can carry additional fields without breaking a
  version-1 parser; see parse_payload() for the documented policy).

Author : CNS Lab Project
"""

import base64
import json
from typing import Any

from crypto.encryption import (
    SALT_LENGTH,
    NONCE_LENGTH,
    KDF_ITERATIONS,
    ALGORITHM_LABEL,
    KDF_LABEL,
)


# ─── Schema constants ────────────────────────────────────────────────────────

PAYLOAD_VERSION: int = 1

# Minimum ciphertext length: AES-GCM always appends a 16-byte authentication
# tag, so a valid ciphertext field must be at least 16 bytes even if the
# original message were empty (which encrypt_message() rejects anyway).
MIN_CIPHERTEXT_BYTES: int = 16

# Required fields in the JSON payload.
REQUIRED_FIELDS: tuple = (
    "version", "algorithm", "kdf", "iterations",
    "salt", "nonce", "ciphertext", "sha256",
)

# Allowlisted values — explicit list prevents algorithm substitution attacks.
ALLOWED_ALGORITHMS: frozenset = frozenset({"AES-256-GCM"})
ALLOWED_KDFS: frozenset       = frozenset({"PBKDF2-HMAC-SHA256"})


# ─── Custom exceptions ───────────────────────────────────────────────────────

class PayloadError(Exception):
    """
    Raised when the payload cannot be built, serialized, parsed, or decoded.

    The Flask extraction route catches this and displays a friendly message
    without exposing internal structure to the user.
    """


# ─── Public API ──────────────────────────────────────────────────────────────

def build_payload(encrypted_data: dict, sha256_digest: bytes) -> dict:
    """
    Combine AES-256-GCM output and SHA-256 digest into a JSON-serializable dict.

    This function is the entry point for the HIDE pipeline.  It takes the
    raw bytes produced by crypto/encryption.py and the digest produced by
    crypto/hashing.py and assembles the versioned payload schema.

    Args:
        encrypted_data : The dictionary returned by encrypt_message().
                         Must contain: salt (bytes), nonce (bytes),
                         ciphertext (bytes), iterations (int).
        sha256_digest  : The 32-byte SHA-256 digest of (salt ‖ nonce ‖ ciphertext)
                         produced by sha256_components() in crypto/hashing.py.

    Returns:
        A Python dict that is directly JSON-serializable:
        {
            "version"    : 1,
            "algorithm"  : "AES-256-GCM",
            "kdf"        : "PBKDF2-HMAC-SHA256",
            "iterations" : 600000,
            "salt"       : "<base64>",
            "nonce"      : "<base64>",
            "ciphertext" : "<base64>",
            "sha256"     : "<64-char lowercase hex>",
        }

    Raises:
        PayloadError : If any required field is missing or has an incorrect type.
    """
    # ── Validate encrypted_data ───────────────────────────────────────────────
    for field in ("salt", "nonce", "ciphertext", "iterations"):
        if field not in encrypted_data:
            raise PayloadError(
                f"encrypted_data is missing required field: '{field}'."
            )

    salt       = encrypted_data["salt"]
    nonce      = encrypted_data["nonce"]
    ciphertext = encrypted_data["ciphertext"]
    iterations = encrypted_data["iterations"]

    _require_bytes(salt,       "salt")
    _require_bytes(nonce,      "nonce")
    _require_bytes(ciphertext, "ciphertext")

    if len(salt) != SALT_LENGTH:
        raise PayloadError(
            f"salt must be {SALT_LENGTH} bytes; got {len(salt)}."
        )
    if len(nonce) != NONCE_LENGTH:
        raise PayloadError(
            f"nonce must be {NONCE_LENGTH} bytes; got {len(nonce)}."
        )
    if len(ciphertext) < MIN_CIPHERTEXT_BYTES:
        raise PayloadError(
            f"ciphertext must be at least {MIN_CIPHERTEXT_BYTES} bytes "
            f"(16-byte GCM auth tag minimum); got {len(ciphertext)}."
        )

    if not isinstance(iterations, int) or iterations <= 0:
        raise PayloadError("iterations must be a positive integer.")

    # ── Validate SHA-256 digest ───────────────────────────────────────────────
    _require_bytes(sha256_digest, "sha256_digest")
    if len(sha256_digest) != 32:
        raise PayloadError(
            f"sha256_digest must be exactly 32 bytes; got {len(sha256_digest)}."
        )

    # ── Assemble payload ──────────────────────────────────────────────────────
    # Binary fields are Base64-encoded so they can be stored as JSON strings.
    # The SHA-256 digest is expressed as lowercase hex (human-readable in the UI).
    return {
        "version"    : PAYLOAD_VERSION,
        "algorithm"  : ALGORITHM_LABEL,    # "AES-256-GCM"
        "kdf"        : KDF_LABEL,           # "PBKDF2-HMAC-SHA256"
        "iterations" : iterations,
        "salt"       : base64.b64encode(salt).decode("ascii"),
        "nonce"      : base64.b64encode(nonce).decode("ascii"),
        "ciphertext" : base64.b64encode(ciphertext).decode("ascii"),
        "sha256"     : sha256_digest.hex(),  # 64-char lowercase hex
    }


def serialize_payload(payload: dict) -> bytes:
    """
    Serialize a payload dict to compact, deterministic UTF-8 JSON bytes.

    The serialization is deterministic because:
      • sort_keys=True  — field order is alphabetical, not insertion-order.
      • separators=(",",":")  — no whitespace between tokens.

    This means the same payload dict always produces the exact same byte
    sequence, which is important for reproducibility and debugging.

    Args:
        payload : A dict produced by build_payload().

    Returns:
        Compact UTF-8-encoded JSON bytes.

    Raises:
        PayloadError : If required fields are missing or serialization fails.
    """
    _validate_payload_schema(payload)

    try:
        json_str: str = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,   # all non-ASCII escaped → safe in any context
        )
        return json_str.encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PayloadError(f"Payload serialization failed: {exc}") from exc


def parse_payload(data: bytes) -> dict:
    """
    Parse and validate raw bytes into a payload dict.

    This is the entry point for the EXTRACT pipeline.  It:
      1. Checks the input is bytes-like.
      2. Decodes UTF-8.
      3. Parses JSON.
      4. Validates that the result is a JSON object (not an array, number …).
      5. Validates every required field.
      6. Returns the validated dict (with base64 fields still as strings).

    Schema policy for unknown fields
    ─────────────────────────────────
    Extra fields that are not part of the version-1 schema are silently
    ignored.  Rationale: a future version-2 payload could include additional
    metadata (e.g. a comment field) without breaking a version-1 parser.
    This is a deliberate forward-compatibility choice.  The allowlisted
    algorithm / KDF / version values still prevent algorithm-substitution
    attacks — only truly unknown extra keys are ignored, not algorithm names.

    Args:
        data : Raw bytes from LSB extraction.

    Returns:
        A validated dict with all required fields present and type-correct.
        Binary fields are still base64 strings at this stage; call
        decode_payload_fields() to convert them to bytes.

    Raises:
        PayloadError : For any structural, encoding, or validation failure.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise PayloadError(
            f"parse_payload() expects bytes, got {type(data).__name__!r}."
        )

    # ── UTF-8 decode ──────────────────────────────────────────────────────────
    try:
        json_str = data.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise PayloadError(
            f"Payload contains invalid UTF-8 data: {exc}"
        ) from exc

    # ── JSON parse ────────────────────────────────────────────────────────────
    try:
        obj: Any = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise PayloadError(
            f"Payload is not valid JSON: {exc}"
        ) from exc

    # ── Must be a JSON object (dict), not an array, string, number … ─────────
    if not isinstance(obj, dict):
        raise PayloadError(
            f"Payload JSON must be an object (dict), got {type(obj).__name__!r}."
        )

    # ── Full schema validation ────────────────────────────────────────────────
    _validate_payload_schema(obj)

    return obj


def decode_payload_fields(payload: dict) -> dict:
    """
    Decode the base64 and hex fields of a validated payload into raw bytes.

    Call this after parse_payload() to get byte values suitable for passing
    to decrypt_message() and sha256_components() for integrity verification.

    Args:
        payload : A validated dict produced by parse_payload() (or build_payload()).

    Returns:
        A new dict with the same metadata fields plus decoded binary fields:
        {
            "version"    : int,
            "algorithm"  : str,
            "kdf"        : str,
            "iterations" : int,
            "salt"       : bytes  (32 bytes),
            "nonce"      : bytes  (12 bytes),
            "ciphertext" : bytes  (≥ 16 bytes),
            "sha256"     : bytes  (32 bytes),
        }

        The "sha256" field is returned as bytes so the calling layer can do a
        direct bytes comparison:  computed_digest == stored_digest.

    Raises:
        PayloadError : If a base64 field cannot be decoded or a hex field
                       is malformed.
    """
    _validate_payload_schema(payload)

    # Decode binary fields.
    salt       = _decode_b64_field(payload["salt"],       "salt",       SALT_LENGTH)
    nonce      = _decode_b64_field(payload["nonce"],      "nonce",      NONCE_LENGTH)
    ciphertext = _decode_b64_field(payload["ciphertext"], "ciphertext", None)

    # ciphertext must still be at least 16 bytes after decoding.
    if len(ciphertext) < MIN_CIPHERTEXT_BYTES:
        raise PayloadError(
            f"Decoded ciphertext is too short: {len(ciphertext)} bytes "
            f"(minimum {MIN_CIPHERTEXT_BYTES})."
        )

    # Decode the SHA-256 hex string to 32 raw bytes for direct comparison.
    sha256_bytes = _decode_hex_field(payload["sha256"], "sha256", expected_bytes=32)

    return {
        "version"    : payload["version"],
        "algorithm"  : payload["algorithm"],
        "kdf"        : payload["kdf"],
        "iterations" : payload["iterations"],
        "salt"       : salt,
        "nonce"      : nonce,
        "ciphertext" : ciphertext,
        "sha256"     : sha256_bytes,
    }


# ─── Internal validation helpers ─────────────────────────────────────────────

def _require_bytes(value: Any, name: str) -> None:
    """Raise PayloadError if *value* is not bytes or bytearray."""
    if not isinstance(value, (bytes, bytearray)):
        raise PayloadError(
            f"Field '{name}' must be bytes, got {type(value).__name__!r}."
        )


def _validate_payload_schema(payload: dict) -> None:
    """
    Validate every required field in *payload* against the version-1 schema.

    This is called by both serialize_payload() (to catch programmer errors
    before embedding a broken payload) and parse_payload() (to catch
    malformed or tampered data received from an image).

    Raises:
        PayloadError on any structural or value mismatch.
    """
    # ── Required fields present ───────────────────────────────────────────────
    for field in REQUIRED_FIELDS:
        if field not in payload:
            raise PayloadError(
                f"Payload is missing required field: '{field}'."
            )

    # ── version ───────────────────────────────────────────────────────────────
    if payload["version"] != PAYLOAD_VERSION:
        raise PayloadError(
            f"Unsupported payload version: {payload['version']!r}. "
            f"Expected {PAYLOAD_VERSION}."
        )

    # ── algorithm ─────────────────────────────────────────────────────────────
    if payload["algorithm"] not in ALLOWED_ALGORITHMS:
        raise PayloadError(
            f"Unsupported algorithm: {payload['algorithm']!r}. "
            f"Allowed: {sorted(ALLOWED_ALGORITHMS)}."
        )

    # ── kdf ───────────────────────────────────────────────────────────────────
    if payload["kdf"] not in ALLOWED_KDFS:
        raise PayloadError(
            f"Unsupported KDF: {payload['kdf']!r}. "
            f"Allowed: {sorted(ALLOWED_KDFS)}."
        )

    # ── iterations ────────────────────────────────────────────────────────────
    if not isinstance(payload["iterations"], int) or payload["iterations"] <= 0:
        raise PayloadError(
            f"Field 'iterations' must be a positive integer; "
            f"got {payload['iterations']!r}."
        )
    if payload["iterations"] != KDF_ITERATIONS:
        raise PayloadError(
            f"Unsupported iteration count: {payload['iterations']}. "
            f"Expected {KDF_ITERATIONS}."
        )

    # ── salt — must be valid base64 and decode to SALT_LENGTH bytes ───────────
    _validate_b64_field(payload["salt"],       "salt",       SALT_LENGTH)

    # ── nonce — must be valid base64 and decode to NONCE_LENGTH bytes ─────────
    _validate_b64_field(payload["nonce"],      "nonce",      NONCE_LENGTH)

    # ── ciphertext — must be valid base64, at least MIN_CIPHERTEXT_BYTES ──────
    _validate_b64_field(payload["ciphertext"], "ciphertext", None)
    ct_bytes = base64.b64decode(payload["ciphertext"])
    if len(ct_bytes) < MIN_CIPHERTEXT_BYTES:
        raise PayloadError(
            f"Ciphertext is too short after Base64 decode: {len(ct_bytes)} bytes "
            f"(minimum {MIN_CIPHERTEXT_BYTES} — the 16-byte GCM auth tag)."
        )

    # ── sha256 — must be exactly 64 lowercase hex characters ─────────────────
    _validate_sha256_hex_field(payload["sha256"])


def _validate_b64_field(value: Any, name: str, expected_bytes: int | None) -> None:
    """
    Validate that *value* is a string, is valid standard Base64, and decodes
    to exactly *expected_bytes* bytes (if specified).

    Args:
        value          : The payload field value.
        name           : Human-readable field name for error messages.
        expected_bytes : Expected decoded length, or None to skip length check.

    Raises:
        PayloadError on any failure.
    """
    if not isinstance(value, str):
        raise PayloadError(
            f"Field '{name}' must be a string (Base64), got {type(value).__name__!r}."
        )
    try:
        # validate=True rejects characters outside the Base64 alphabet and
        # incorrect padding — no silent substitution.
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise PayloadError(
            f"Field '{name}' is not valid Base64: {exc}"
        ) from exc

    if expected_bytes is not None and len(decoded) != expected_bytes:
        raise PayloadError(
            f"Field '{name}' decodes to {len(decoded)} bytes; "
            f"expected {expected_bytes}."
        )


def _validate_sha256_hex_field(value: Any) -> None:
    """
    Validate that *value* is a 64-character lowercase hexadecimal string.

    Raises:
        PayloadError if the field is invalid.
    """
    if not isinstance(value, str):
        raise PayloadError(
            f"Field 'sha256' must be a string, got {type(value).__name__!r}."
        )
    if len(value) != 64:
        raise PayloadError(
            f"Field 'sha256' must be exactly 64 characters; got {len(value)}."
        )

    # Check every character is a valid lowercase hex digit.
    valid_hex = frozenset("0123456789abcdef")
    invalid   = [c for c in value if c not in valid_hex]
    if invalid:
        raise PayloadError(
            f"Field 'sha256' contains non-hex or uppercase characters: "
            f"{list(set(invalid))}."
        )


def _decode_b64_field(value: str, name: str, expected_bytes: int | None) -> bytes:
    """
    Decode a Base64 string field to bytes, with optional length validation.

    Args:
        value          : Base64 string from the payload dict.
        name           : Field name for error messages.
        expected_bytes : Expected decoded length, or None to skip.

    Returns:
        Decoded bytes.

    Raises:
        PayloadError on failure.
    """
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise PayloadError(
            f"Failed to Base64-decode field '{name}': {exc}"
        ) from exc

    if expected_bytes is not None and len(decoded) != expected_bytes:
        raise PayloadError(
            f"Field '{name}' decoded to {len(decoded)} bytes; "
            f"expected {expected_bytes}."
        )
    return decoded


def _decode_hex_field(value: str, name: str, expected_bytes: int) -> bytes:
    """
    Decode a lowercase hex string field to bytes.

    Args:
        value          : Hex string from the payload dict.
        name           : Field name for error messages.
        expected_bytes : Expected decoded byte length.

    Returns:
        Decoded bytes.

    Raises:
        PayloadError on failure.
    """
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise PayloadError(
            f"Failed to hex-decode field '{name}': {exc}"
        ) from exc

    if len(decoded) != expected_bytes:
        raise PayloadError(
            f"Field '{name}' hex-decoded to {len(decoded)} bytes; "
            f"expected {expected_bytes}."
        )
    return decoded
