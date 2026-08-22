"""
tests/test_crypto.py
────────────────────
Automated tests for the crypto/encryption.py module.

Tests cover:
  1.  Basic encrypt → decrypt round trip.
  2.  Unicode message round trip.
  3.  Empty message rejected.
  4.  Empty password rejected.
  5.  Wrong password rejected.
  6.  Same inputs produce different ciphertext (randomness of salt/nonce).
  7.  Same password + different salt → different derived key.
  8.  Tampered ciphertext is rejected by AES-GCM authentication.
  9.  Derived AES key length is 32 bytes.
  10. Salt length is 32 bytes.
  11. Nonce length is 12 bytes.

Run with:
    pytest tests/test_crypto.py -v
"""

import pytest

from crypto.encryption import (
    encrypt_message,
    decrypt_message,
    get_key_for_testing,
    InvalidInputError,
    DecryptionError,
    SALT_LENGTH,
    KEY_LENGTH,
    NONCE_LENGTH,
    KDF_ITERATIONS,
)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1 — Basic encrypt / decrypt round trip
# ─────────────────────────────────────────────────────────────────────────────

def test_basic_round_trip():
    """
    Encrypt a simple ASCII message, then decrypt with the same password.
    The recovered plaintext must exactly match the original.
    """
    message  = "Hello CNS Lab"
    password = "test1234"

    encrypted = encrypt_message(message, password)
    recovered = decrypt_message(encrypted, password)

    assert recovered == message, (
        f"Round-trip failed: expected {message!r}, got {recovered!r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2 — Unicode message round trip
# ─────────────────────────────────────────────────────────────────────────────

def test_unicode_round_trip():
    """
    Encrypt a message containing Unicode characters (emoji + Devanagari script).
    The module must handle multi-byte UTF-8 encoding/decoding correctly.
    """
    message  = "Hello 🔐 CNS — नमस्ते"
    password = "unicode_test_pass"

    encrypted = encrypt_message(message, password)
    recovered = decrypt_message(encrypted, password)

    assert recovered == message


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3 — Empty message rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_empty_message_rejected():
    """
    encrypt_message() must raise InvalidInputError when message is empty.
    We must never silently encrypt an empty string.
    """
    with pytest.raises(InvalidInputError):
        encrypt_message("", "somepassword")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 4 — Empty password rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_empty_password_rejected():
    """
    encrypt_message() must raise InvalidInputError when password is empty.
    """
    with pytest.raises(InvalidInputError):
        encrypt_message("Some message", "")


def test_empty_password_rejected_on_decrypt():
    """
    decrypt_message() must raise InvalidInputError when password is empty,
    even before attempting any cryptographic operation.
    """
    encrypted = encrypt_message("Some message", "realpassword")
    with pytest.raises(InvalidInputError):
        decrypt_message(encrypted, "")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 5 — Wrong password rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_wrong_password_rejected():
    """
    Decrypting with a different password must raise DecryptionError.

    Because PBKDF2 with the wrong password produces a different AES key,
    the AES-GCM authentication tag will not match and the library will raise
    InvalidTag — which we wrap in DecryptionError.
    """
    message       = "Secret message"
    correct_pass  = "correct_password"
    wrong_pass    = "wrong_password"

    encrypted = encrypt_message(message, correct_pass)

    with pytest.raises(DecryptionError):
        decrypt_message(encrypted, wrong_pass)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 6 — Same inputs produce different ciphertexts (salt + nonce randomness)
# ─────────────────────────────────────────────────────────────────────────────

def test_same_input_different_ciphertext():
    """
    Encrypting the same message with the same password twice MUST produce
    different ciphertext values.

    This is guaranteed by the random salt (which changes the AES key) and
    the random nonce (which changes the keystream).  If this test were to fail
    it would indicate that either the salt or nonce is not truly random —
    a serious cryptographic flaw.
    """
    message  = "Repeated message"
    password = "samepassword"

    enc1 = encrypt_message(message, password)
    enc2 = encrypt_message(message, password)

    # Both salt and nonce must differ (astronomically unlikely to collide).
    assert enc1["salt"]       != enc2["salt"],       "Salts must be unique per encryption"
    assert enc1["nonce"]      != enc2["nonce"],       "Nonces must be unique per encryption"
    assert enc1["ciphertext"] != enc2["ciphertext"],  "Ciphertexts must differ when salt/nonce differ"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 7 — Different salts produce different derived keys
# ─────────────────────────────────────────────────────────────────────────────

def test_different_salt_different_key():
    """
    PBKDF2 with the same password but different salts must produce different
    AES keys.  This is the core purpose of the salt: preventing an attacker
    from precomputing a single key for a given password.
    """
    import os
    password = "shared_password"

    salt1 = os.urandom(SALT_LENGTH)
    salt2 = os.urandom(SALT_LENGTH)

    # Ensure the two random salts actually differ (trivially true; just guards
    # against a broken os.urandom).
    assert salt1 != salt2, "Random salts must differ"

    key1 = get_key_for_testing(password, salt1)
    key2 = get_key_for_testing(password, salt2)

    assert key1 != key2, (
        "Same password + different salt must produce different derived keys"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST 8 — Tampered ciphertext is rejected by AES-GCM authentication
# ─────────────────────────────────────────────────────────────────────────────

def test_tampered_ciphertext_rejected():
    """
    AES-256-GCM provides authenticated encryption.  Any modification to the
    ciphertext (even flipping a single bit) must cause decryption to fail.

    This test demonstrates the integrity guarantee of AES-GCM that is
    independent of the SHA-256 layer added in Phase 3.
    """
    message  = "Tamper-proof message"
    password = "tamper_test_pass"

    encrypted = encrypt_message(message, password)

    # Flip the first byte of the ciphertext.
    original_ct   = encrypted["ciphertext"]
    tampered_byte = bytes([original_ct[0] ^ 0xFF])   # XOR with 0xFF flips all bits
    tampered_ct   = tampered_byte + original_ct[1:]

    tampered_data             = dict(encrypted)
    tampered_data["ciphertext"] = tampered_ct

    with pytest.raises(DecryptionError):
        decrypt_message(tampered_data, password)


def test_tampered_ciphertext_middle_byte_rejected():
    """
    Tampering a byte in the middle of the ciphertext must also be rejected.
    """
    message  = "Another tamper test"
    password = "tamper_test_pass_2"

    encrypted = encrypt_message(message, password)
    original_ct = encrypted["ciphertext"]

    # Flip a byte in the middle.
    mid = len(original_ct) // 2
    tampered_ct = (
        original_ct[:mid]
        + bytes([original_ct[mid] ^ 0x01])
        + original_ct[mid + 1:]
    )

    tampered_data               = dict(encrypted)
    tampered_data["ciphertext"] = tampered_ct

    with pytest.raises(DecryptionError):
        decrypt_message(tampered_data, password)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 9 — AES key length is 32 bytes (AES-256)
# ─────────────────────────────────────────────────────────────────────────────

def test_key_length_is_32_bytes():
    """
    The derived AES key must be exactly 32 bytes (256 bits).
    AES-256 requires a 256-bit key; any other length would silently select
    AES-128 or AES-192 or raise an error in the library.
    """
    import os
    password = "key_length_test"
    salt     = os.urandom(SALT_LENGTH)

    key = get_key_for_testing(password, salt)

    assert len(key) == KEY_LENGTH, (
        f"Expected key length {KEY_LENGTH}, got {len(key)}"
    )
    assert KEY_LENGTH == 32, "KEY_LENGTH constant must be 32 for AES-256"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 10 — Salt length is 32 bytes
# ─────────────────────────────────────────────────────────────────────────────

def test_salt_length_is_32_bytes():
    """
    The randomly generated salt must be exactly 32 bytes.
    """
    encrypted = encrypt_message("Salt length test", "saltpass")
    salt = encrypted["salt"]

    assert isinstance(salt, bytes), "Salt must be bytes"
    assert len(salt) == SALT_LENGTH, (
        f"Expected salt length {SALT_LENGTH}, got {len(salt)}"
    )
    assert SALT_LENGTH == 32, "SALT_LENGTH constant must be 32"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 11 — Nonce length is 12 bytes
# ─────────────────────────────────────────────────────────────────────────────

def test_nonce_length_is_12_bytes():
    """
    The randomly generated GCM nonce must be exactly 12 bytes.
    12 bytes (96 bits) is the standard nonce length for AES-GCM.
    Other lengths require an extra GHASH derivation step, which is less
    efficient and less standardised.
    """
    encrypted = encrypt_message("Nonce length test", "noncepass")
    nonce = encrypted["nonce"]

    assert isinstance(nonce, bytes), "Nonce must be bytes"
    assert len(nonce) == NONCE_LENGTH, (
        f"Expected nonce length {NONCE_LENGTH}, got {len(nonce)}"
    )
    assert NONCE_LENGTH == 12, "NONCE_LENGTH constant must be 12"


# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONAL — Metadata fields are present and correct
# ─────────────────────────────────────────────────────────────────────────────

def test_encrypted_dict_has_required_fields():
    """
    The dictionary returned by encrypt_message() must contain all fields
    required by the decryption function and the future payload module.
    """
    result = encrypt_message("Field check", "fieldpass")

    assert "salt"       in result
    assert "nonce"      in result
    assert "ciphertext" in result
    assert "iterations" in result
    assert "algorithm"  in result
    assert "kdf"        in result

    assert result["iterations"] == KDF_ITERATIONS
    assert result["algorithm"]  == "AES-256-GCM"
    assert result["kdf"]        == "PBKDF2-HMAC-SHA256"


def test_ciphertext_is_bytes():
    """
    All binary fields returned by encrypt_message() must be raw bytes,
    not strings or base64.  The payload layer handles serialisation.
    """
    result = encrypt_message("Bytes check", "bytespass")

    assert isinstance(result["salt"],       bytes), "salt must be bytes"
    assert isinstance(result["nonce"],      bytes), "nonce must be bytes"
    assert isinstance(result["ciphertext"], bytes), "ciphertext must be bytes"


def test_ciphertext_longer_than_plaintext():
    """
    The AES-GCM ciphertext field (ciphertext || tag) must be at least
    16 bytes longer than the plaintext because the authentication tag
    is always 16 bytes.
    """
    message  = "Length check"
    password = "lengthpass"

    result = encrypt_message(message, password)

    plaintext_len  = len(message.encode("utf-8"))
    ciphertext_len = len(result["ciphertext"])

    # ciphertext = encrypted_message (same length as plaintext) + 16-byte tag
    assert ciphertext_len == plaintext_len + 16, (
        f"Expected ciphertext length {plaintext_len + 16}, got {ciphertext_len}"
    )


def test_missing_field_raises_invalid_input():
    """
    decrypt_message() must raise InvalidInputError if a required field is
    missing from the encrypted_data dictionary.
    """
    encrypted = encrypt_message("Missing field test", "pass123")

    for field in ("salt", "nonce", "ciphertext", "iterations"):
        broken = dict(encrypted)
        del broken[field]
        with pytest.raises(InvalidInputError):
            decrypt_message(broken, "pass123")


def test_non_string_message_rejected():
    """
    encrypt_message() must reject non-string message types.
    """
    with pytest.raises(InvalidInputError):
        encrypt_message(12345, "password")  # type: ignore[arg-type]


def test_non_string_password_rejected():
    """
    encrypt_message() must reject non-string password types.
    """
    with pytest.raises(InvalidInputError):
        encrypt_message("message", None)  # type: ignore[arg-type]
