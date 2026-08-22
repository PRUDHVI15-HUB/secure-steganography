"""
crypto/encryption.py
────────────────────
AES-256-GCM encryption and decryption with PBKDF2-HMAC-SHA256 key derivation.

Security design overview
────────────────────────
1.  PASSWORD → KEY  (PBKDF2-HMAC-SHA256)
    The user's password is never used directly as an AES key.  Raw passwords
    are typically short, low-entropy strings that would make a very weak key.
    PBKDF2 stretches the password through many iterated hash rounds and mixes
    in a random salt, producing a uniformly-distributed 256-bit key regardless
    of how weak the password is.

    Parameters chosen:
      • Salt   : 32 bytes, cryptographically random, unique per encryption.
                 The salt does not need to be secret; it is stored alongside
                 the ciphertext so decryption can reproduce the same key.
      • Key    : 32 bytes  (AES-256 requires exactly 256 bits).
      • Iterations : 600,000  — a strong password-based key derivation setting
                 based on current industry guidance.  More iterations mean
                 more work for an attacker trying to brute-force the password.
      • Hash   : SHA-256.

2.  ENCRYPTION  (AES-256-GCM)
    AES-256 is a symmetric block cipher with a 256-bit key.  GCM
    (Galois/Counter Mode) turns it into an authenticated encryption scheme:
      • Confidentiality   : the ciphertext reveals nothing about the plaintext.
      • Integrity / Auth  : a 16-byte authentication tag is appended to the
                            ciphertext.  Any modification of the ciphertext
                            (even a single bit) causes decryption to fail.
    This means AES-256-GCM simultaneously encrypts and authenticates the data.

    Parameters:
      • Key    : 32-byte derived key (from PBKDF2, above).
      • Nonce  : 12 bytes, cryptographically random, unique per encryption.
                 The nonce must NEVER be reused with the same key.  Nonce
                 reuse under GCM is catastrophic — it can expose the key and
                 plaintext.  Generating a fresh random nonce for every
                 encryption operation keeps the probability of collision
                 negligible.

    Python's `cryptography` library AESGCM.encrypt() returns:
        ciphertext || authentication_tag
    as a single byte string (the tag is always the last 16 bytes).
    We store this combined value in the "ciphertext" field as-is.
    The payload serialisation layer (payload.py, Phase 4) will handle
    base64 encoding for JSON transport.

    We intentionally DO NOT:
      • implement AES manually
      • use ECB or CBC mode
      • hardcode any key, password, salt, or nonce
      • use random.random() or any non-CSPRNG source

Author : CNS Lab Project
"""

import os
from typing import Any

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# ─── Constants ───────────────────────────────────────────────────────────────

# Number of PBKDF2 iterations.
# A strong password-based key derivation setting based on current industry
# guidance.  Higher iteration counts slow down brute-force attacks.
KDF_ITERATIONS: int = 600_000

# Salt length in bytes (32 bytes = 256 bits).
SALT_LENGTH: int = 32

# AES key length in bytes (32 bytes = 256 bits → AES-256).
KEY_LENGTH: int = 32

# GCM nonce length in bytes.  12 bytes is the standard recommended length
# for AES-GCM; other lengths require an extra GHASH step internally.
NONCE_LENGTH: int = 12

# Human-readable metadata stored alongside the ciphertext.
ALGORITHM_LABEL: str = "AES-256-GCM"
KDF_LABEL: str = "PBKDF2-HMAC-SHA256"


# ─── Custom exceptions ───────────────────────────────────────────────────────

class InvalidInputError(ValueError):
    """
    Raised when the caller supplies invalid or empty input values.

    The Flask layer will later convert this into a user-facing error message
    without exposing any internal details.
    """


class DecryptionError(Exception):
    """
    Raised when decryption fails for any reason:
      • Wrong password (key derivation produces a different key).
      • Tampered / corrupted ciphertext (AES-GCM auth tag rejected).
      • Missing or malformed fields in the encrypted-data dictionary.

    The Flask layer will convert this into a generic friendly message.
    Callers must NOT expose the original exception message to end users.
    """


# ─── Internal helpers ────────────────────────────────────────────────────────

def _validate_str(value: Any, name: str) -> None:
    """
    Assert that *value* is a non-empty string.

    Args:
        value : The value to check.
        name  : Human-readable field name used in the error message.

    Raises:
        InvalidInputError : If *value* is not a non-empty string.
    """
    if not isinstance(value, str):
        raise InvalidInputError(f"{name} must be a string.")
    if not value:
        raise InvalidInputError(f"{name} must not be empty.")


def _generate_salt() -> bytes:
    """
    Generate a cryptographically random 32-byte salt.

    The salt is public information stored with the ciphertext.  Its purpose
    is to ensure that two encryptions of the same password produce different
    derived keys, preventing precomputed (rainbow-table) attacks.

    Returns:
        32 random bytes from the OS CSPRNG.
    """
    return os.urandom(SALT_LENGTH)


def _generate_nonce() -> bytes:
    """
    Generate a cryptographically random 12-byte GCM nonce.

    The nonce (number used once) must be unique for every encryption operation
    that uses the same AES key.  Reusing a nonce under GCM can reveal the
    authentication key and allow the attacker to decrypt or forge ciphertext.

    Returns:
        12 random bytes from the OS CSPRNG.
    """
    return os.urandom(NONCE_LENGTH)


def _derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Derive a 32-byte AES key from *password* and *salt* using PBKDF2-HMAC-SHA256.

    Args:
        password   : The user's password (plaintext string).
        salt       : A random 32-byte salt (generated per encryption).
        iterations : Number of PBKDF2 iterations (default: KDF_ITERATIONS).

    Returns:
        32-byte derived key suitable for AES-256.

    Notes:
        The derived key is a deterministic function of (password, salt,
        iterations).  Given the same three inputs, the same key is reproduced —
        which is how decryption works without ever storing the key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=iterations,
    )
    # Encode password as UTF-8 bytes before passing to PBKDF2.
    return kdf.derive(password.encode("utf-8"))


# ─── Public API ──────────────────────────────────────────────────────────────

def encrypt_message(message: str, password: str) -> dict:
    """
    Encrypt *message* with *password* using AES-256-GCM.

    The password is never used directly as the encryption key.  Instead,
    PBKDF2-HMAC-SHA256 derives a 256-bit key from the password + a fresh
    random salt.  A fresh random 12-byte nonce is generated for each call.

    Args:
        message  : The plaintext secret message (UTF-8 string).
        password : The user's password (UTF-8 string).

    Returns:
        A dictionary with the following fields (all binary fields are raw bytes):

        {
            "salt"       : bytes  — 32-byte random PBKDF2 salt,
            "nonce"      : bytes  — 12-byte random GCM nonce,
            "ciphertext" : bytes  — AES-GCM output: encrypted data +
                                    16-byte authentication tag (combined),
            "iterations" : int    — KDF iteration count (needed for decryption),
            "algorithm"  : str    — "AES-256-GCM",
            "kdf"        : str    — "PBKDF2-HMAC-SHA256",
        }

        NOTE on ciphertext field:
        Python's AESGCM.encrypt() returns  ciphertext ‖ tag  as one byte string.
        The authentication tag is always the LAST 16 bytes.  We store the
        combined value as-is.  The payload layer (payload.py) will later
        base64-encode it for JSON transport.

    Raises:
        InvalidInputError : If *message* or *password* is empty or not a string.
    """
    # ── Input validation ──────────────────────────────────────────────────────
    _validate_str(message,  "Message")
    _validate_str(password, "Password")

    # ── Key material generation ───────────────────────────────────────────────
    salt  = _generate_salt()   # 32 random bytes  — stored in payload
    nonce = _generate_nonce()  # 12 random bytes  — stored in payload

    # Derive a 32-byte AES key from the password + salt.
    # The key itself is NEVER stored anywhere.
    key = _derive_key(password, salt)

    # ── Encryption ────────────────────────────────────────────────────────────
    aesgcm = AESGCM(key)

    # Encode the plaintext message as UTF-8 bytes.
    plaintext_bytes = message.encode("utf-8")

    # AESGCM.encrypt(nonce, plaintext, aad) → ciphertext || tag
    # We pass None for the additional authenticated data (aad) since we
    # are not authenticating any extra context in this phase.
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)

    # ── Return result ─────────────────────────────────────────────────────────
    return {
        "salt"       : salt,
        "nonce"      : nonce,
        "ciphertext" : ciphertext_with_tag,   # encrypted_data || 16-byte GCM tag
        "iterations" : KDF_ITERATIONS,
        "algorithm"  : ALGORITHM_LABEL,
        "kdf"        : KDF_LABEL,
    }


def decrypt_message(encrypted_data: dict, password: str) -> str:
    """
    Decrypt a message previously encrypted by encrypt_message().

    Args:
        encrypted_data : The dictionary returned by encrypt_message().
        password       : The password used during encryption.

    Returns:
        The original plaintext message as a UTF-8 string.

    Raises:
        InvalidInputError : If *password* is empty / not a string, or if
                            required fields are missing from *encrypted_data*.
        DecryptionError   : If the password is wrong OR the ciphertext has
                            been tampered with.  AES-GCM authentication will
                            reject any modification to the ciphertext or tag.
    """
    # ── Input validation ──────────────────────────────────────────────────────
    _validate_str(password, "Password")

    required_fields = ("salt", "nonce", "ciphertext", "iterations")
    for field in required_fields:
        if field not in encrypted_data:
            raise InvalidInputError(
                f"Encrypted data is missing required field: '{field}'."
            )

    salt             = encrypted_data["salt"]
    nonce            = encrypted_data["nonce"]
    ciphertext_tag   = encrypted_data["ciphertext"]  # ciphertext || tag
    iterations       = encrypted_data["iterations"]

    # Basic type checks on the recovered fields.
    for field_name, field_val in [("salt", salt), ("nonce", nonce),
                                   ("ciphertext", ciphertext_tag)]:
        if not isinstance(field_val, (bytes, bytearray)):
            raise InvalidInputError(
                f"Field '{field_name}' must be bytes."
            )

    if not isinstance(iterations, int) or iterations <= 0:
        raise InvalidInputError("Field 'iterations' must be a positive integer.")

    # ── Key re-derivation ─────────────────────────────────────────────────────
    # Re-derive the exact same key using the stored salt + the supplied password.
    # If the password is wrong, the derived key will be different and AES-GCM
    # will reject the ciphertext when it verifies the authentication tag.
    key = _derive_key(password, salt, iterations)

    # ── Decryption ────────────────────────────────────────────────────────────
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_tag, None)
    except InvalidTag:
        # AES-GCM raised InvalidTag — either the password was wrong (key
        # mismatch) or the ciphertext/tag was tampered with.
        # We raise a single unified DecryptionError so callers don't need to
        # distinguish between the two failure modes (and so we don't leak
        # information about which field caused the failure).
        raise DecryptionError(
            "Decryption failed. The password may be incorrect or the "
            "encrypted data may have been tampered with."
        )
    except Exception as exc:
        # Catch any other unexpected cryptography errors and wrap them so that
        # no internal stack detail leaks through to the calling layer.
        raise DecryptionError(
            f"An unexpected error occurred during decryption."
        ) from exc

    # ── Decode and return ─────────────────────────────────────────────────────
    return plaintext_bytes.decode("utf-8")


# ─── Utility (used by payload.py and analysis) ───────────────────────────────

def get_key_for_testing(password: str, salt: bytes,
                        iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Re-derive the AES key given a password and salt.

    This function exists ONLY for use in automated tests that need to verify
    key length / properties.  It must NOT be called in production code paths
    where the key could be inadvertently logged or stored.

    Args:
        password   : The password string.
        salt       : The salt bytes.
        iterations : PBKDF2 iteration count.

    Returns:
        The 32-byte derived AES key.
    """
    return _derive_key(password, salt, iterations)
