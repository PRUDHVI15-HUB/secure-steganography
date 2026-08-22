"""
crypto/hashing.py
─────────────────
SHA-256 cryptographic hashing utilities.

Academic clarification — important for the CNS viva
─────────────────────────────────────────────────────
This module provides SHA-256 hashing.  SHA-256 is fundamentally different
from AES-256-GCM:

  AES-256-GCM (crypto/encryption.py)
    • Symmetric encryption — transforms plaintext into ciphertext.
    • Provides CONFIDENTIALITY: ciphertext reveals nothing about plaintext.
    • Provides AUTHENTICATED ENCRYPTION: the 16-byte GCM tag detects any
      tampering with the ciphertext.
    • Is reversible — correct key + nonce → original plaintext.

  SHA-256 (this module)
    • Cryptographic hash function — maps arbitrary-length input to a fixed
      256-bit (32-byte) digest.
    • Is ONE-WAY: given only the digest, it is computationally infeasible
      to recover the original input.
    • Is COLLISION-RESISTANT: it is computationally infeasible to find two
      different inputs that produce the same digest.
    • Does NOT provide confidentiality — the digest does NOT hide the input
      from an attacker who already knows what the input is.
    • Does NOT encrypt data.
    • Does NOT replace the authentication provided by AES-GCM.

Role of SHA-256 in this project
────────────────────────────────
Our project includes SHA-256 as a separate, independently demonstrated
component of the CNS pipeline.  The SHA-256 digest of:

    salt ‖ nonce ‖ ciphertext

is embedded inside the steganography payload alongside the AES-GCM
ciphertext.  During extraction, the digest is recomputed over the same
fields and compared against the stored value.  A mismatch indicates that
the payload has been modified (e.g., by pixel-level editing of the stego
image).

This is an additional integrity layer that operates at the payload level,
separate from the byte-level authentication provided by AES-GCM's own tag.
The distinction is explained explicitly in the About page.

NOTE: There is no 'decrypt_hash', 'reverse_hash', or 'decode_hash' function
in this module.  SHA-256 is a one-way function — reversal is not possible.

Author : CNS Lab Project
"""

import hashlib


# ─── Public API ──────────────────────────────────────────────────────────────

def sha256_bytes(data: bytes) -> bytes:
    """
    Compute the SHA-256 digest of *data* and return it as raw bytes.

    Args:
        data : The input data to hash.  Must be a bytes-like object.
               Arbitrary Python objects are NOT silently converted — this
               prevents accidentally hashing a string representation such
               as b"b'...'" instead of the actual binary content.

    Returns:
        A 32-byte (256-bit) SHA-256 digest.

    Raises:
        TypeError : If *data* is not a bytes-like object.

    Example:
        >>> sha256_bytes(b"Hello CNS Lab")
        b'\\x...\\x...'   # 32 raw bytes

    SHA-256 properties:
        • Deterministic   : same input always produces the same digest.
        • One-way         : the digest cannot be reversed to recover the input.
        • Fixed output    : always 32 bytes, regardless of input length.
        • Avalanche effect: a one-bit change in input changes ~50% of output bits.
    """
    _validate_bytes(data, "data")
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """
    Compute the SHA-256 digest of *data* and return it as a lowercase
    hexadecimal string.

    Args:
        data : The input data to hash.  Must be a bytes-like object.

    Returns:
        A 64-character lowercase hexadecimal string representing the
        256-bit SHA-256 digest.

    Raises:
        TypeError : If *data* is not a bytes-like object.

    Example:
        >>> sha256_hex(b"")
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    """
    _validate_bytes(data, "data")
    return hashlib.sha256(data).hexdigest()


def sha256_components(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Compute SHA-256 over the concatenation:  salt ‖ nonce ‖ ciphertext.

    This function is used to generate the integrity digest that is embedded
    in the steganography payload.  During extraction, the same function is
    called on the recovered fields; the results are compared to detect
    any modification to the payload.

    Byte ordering (deterministic and documented):
        [salt bytes] [nonce bytes] [ciphertext bytes]

    Why sequential .update() instead of concatenation?
        Using hashlib's incremental .update() interface feeds each component
        into the SHA-256 state machine without creating a temporary in-memory
        copy of the full concatenated byte string.  This is more memory-
        efficient for large ciphertexts and is semantically identical to
        hashing  salt + nonce + ciphertext  as a single byte string.

    Args:
        salt       : The PBKDF2 salt (32 bytes).
        nonce      : The AES-GCM nonce (12 bytes).
        ciphertext : The AES-GCM output — encrypted data + 16-byte auth tag.

    Returns:
        A 32-byte SHA-256 digest of salt ‖ nonce ‖ ciphertext.

    Raises:
        TypeError : If any argument is not a bytes-like object.

    Example:
        >>> digest = sha256_components(salt, nonce, ciphertext)
        >>> len(digest)
        32
    """
    _validate_bytes(salt,       "salt")
    _validate_bytes(nonce,      "nonce")
    _validate_bytes(ciphertext, "ciphertext")

    # Feed each component into the SHA-256 state in fixed order.
    # This is exactly equivalent to hashlib.sha256(salt + nonce + ciphertext)
    # but avoids allocating the full concatenated byte string.
    hasher = hashlib.sha256()
    hasher.update(salt)
    hasher.update(nonce)
    hasher.update(ciphertext)
    return hasher.digest()


def sha256_components_hex(salt: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """
    Same as sha256_components() but returns a 64-character hex string.

    This convenience function is used by the Flask routes when the UI
    needs to display the integrity digest as a human-readable hex value.

    Args:
        salt       : The PBKDF2 salt (32 bytes).
        nonce      : The AES-GCM nonce (12 bytes).
        ciphertext : The AES-GCM output — encrypted data + 16-byte auth tag.

    Returns:
        A 64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        TypeError : If any argument is not a bytes-like object.
    """
    return sha256_components(salt, nonce, ciphertext).hex()


# ─── Internal helpers ────────────────────────────────────────────────────────

def _validate_bytes(value: object, name: str) -> None:
    """
    Assert that *value* is a bytes-like object.

    We do NOT silently convert strings or other objects because that could
    produce subtly wrong digests (e.g., hashing the repr "b'\\x00'" instead
    of the actual null byte).

    Args:
        value : The value to check.
        name  : Human-readable argument name for the error message.

    Raises:
        TypeError : If *value* is not bytes or bytearray.
    """
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(
            f"Argument '{name}' must be bytes or bytearray, "
            f"got {type(value).__name__!r}."
        )
