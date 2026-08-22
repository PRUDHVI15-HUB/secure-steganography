"""
tests/test_security_audit.py
─────────────────────────────
Comprehensive security, failure-resilience, and edge-case test suite (Phase 10).

Coverage:
  1. Cryptography Failure Resilience (AES-GCM tag, nonce, salt tampering, IND-CPA)
  2. SHA-256 Avalanche & Component Reordering Security
  3. Malformed & Malicious Payload Defenses
  4. Steganography Resource Exhaustion & OOM Defenses (Header length spoofing)
  5. Image Validation & Disallowed Format Security (JPEG, WebP, GIF, TXT)
  6. Path Traversal Defenses (/download/ route)
  7. Session Privacy & Key Isolation Audits
  8. End-to-End Multi-Language & Tamper Detection Resilience

Run with:
    pytest tests/test_security_audit.py -v
"""

import io
import json
import re
import struct
import numpy as np
from PIL import Image
import pytest

from app import create_app
from crypto.encryption import encrypt_message, decrypt_message, DecryptionError
from crypto.hashing import sha256_components
from steganography.lsb import (
    embed_payload,
    extract_payload,
    ExtractionError,
)
from utils.payload import (
    parse_payload,
    decode_payload_fields,
    PayloadError,
)
from utils.validators import (
    validate_image_file,
    sanitize_filename,
    ImageFormatError,
    ImageContentError,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def app():
    test_app = create_app()
    test_app.config.update({
        "TESTING": True,
        "DEBUG": False,
        "WTF_CSRF_ENABLED": False,
    })
    yield test_app


@pytest.fixture
def client(app):
    return app.test_client()


def _make_image_bytes(format_name="PNG", size=(150, 150), mode="RGB", color=(70, 100, 140)):
    img = Image.new(mode, size, color=color)
    buf = io.BytesIO()
    img.save(buf, format=format_name)
    buf.seek(0)
    return buf


# ─────────────────────────────────────────────────────────────────────────────
# 1. Cryptography Failure Resilience & Semantic Security
# ─────────────────────────────────────────────────────────────────────────────

def test_aes_gcm_tag_modification_fails():
    """Modifying even one bit of the 16-byte GCM authentication tag fails decryption."""
    encrypted = encrypt_message("Confidential Message", "Passphrase@123")
    ct = bytearray(encrypted["ciphertext"])
    # The GCM tag is the final 16 bytes of ciphertext
    ct[-1] ^= 0x01
    tampered = {
        "salt": encrypted["salt"],
        "nonce": encrypted["nonce"],
        "ciphertext": bytes(ct),
        "iterations": encrypted["iterations"],
    }
    with pytest.raises(DecryptionError):
        decrypt_message(tampered, "Passphrase@123")


def test_aes_gcm_nonce_modification_fails():
    """Modifying the 12-byte nonce fails authenticated decryption."""
    encrypted = encrypt_message("Confidential Message", "Passphrase@123")
    tampered_nonce = bytearray(encrypted["nonce"])
    tampered_nonce[0] ^= 0xFF
    tampered = {
        "salt": encrypted["salt"],
        "nonce": bytes(tampered_nonce),
        "ciphertext": encrypted["ciphertext"],
        "iterations": encrypted["iterations"],
    }
    with pytest.raises(DecryptionError):
        decrypt_message(tampered, "Passphrase@123")


def test_aes_gcm_salt_modification_fails():
    """Modifying the salt derives a completely wrong AES key, failing decryption."""
    encrypted = encrypt_message("Confidential Message", "Passphrase@123")
    tampered_salt = bytearray(encrypted["salt"])
    tampered_salt[0] ^= 0x01
    tampered = {
        "salt": bytes(tampered_salt),
        "nonce": encrypted["nonce"],
        "ciphertext": encrypted["ciphertext"],
        "iterations": encrypted["iterations"],
    }
    with pytest.raises(DecryptionError):
        decrypt_message(tampered, "Passphrase@123")


def test_aes_gcm_truncated_ciphertext_fails():
    """Ciphertext shorter than the 16-byte tag must raise DecryptionError."""
    encrypted = encrypt_message("Confidential Message", "Passphrase@123")
    tampered = {
        "salt": encrypted["salt"],
        "nonce": encrypted["nonce"],
        "ciphertext": encrypted["ciphertext"][:8],
        "iterations": encrypted["iterations"],
    }
    with pytest.raises((DecryptionError, ValueError)):
        decrypt_message(tampered, "Passphrase@123")


def test_ind_cpa_semantic_security():
    """Encrypting the exact same message with the same password produces unique nonces & ciphertexts."""
    msg = "Constant Message"
    pwd = "ConstantPassword"
    enc1 = encrypt_message(msg, pwd)
    enc2 = encrypt_message(msg, pwd)

    assert enc1["salt"] != enc2["salt"]
    assert enc1["nonce"] != enc2["nonce"]
    assert enc1["ciphertext"] != enc2["ciphertext"]


def test_key_isolation_in_encrypted_dict():
    """The derived key must never be included in the encryption output dict."""
    encrypted = encrypt_message("Secret", "Password")
    assert "key" not in encrypted
    assert "derived_key" not in encrypted
    assert "password" not in encrypted


# ─────────────────────────────────────────────────────────────────────────────
# 2. SHA-256 Avalanche & Component Ordering
# ─────────────────────────────────────────────────────────────────────────────

def test_sha256_single_bit_avalanche():
    """A 1-bit change in input changes approximately 50% of the output digest bits."""
    salt = b"\x00" * 32
    nonce = b"\x00" * 12
    ct = b"Hello World Ciphertext 12345"

    d1 = sha256_components(salt, nonce, ct)

    # Flip 1 bit in ciphertext
    ct_flipped = bytearray(ct)
    ct_flipped[0] ^= 0x01
    d2 = sha256_components(salt, nonce, bytes(ct_flipped))

    assert d1 != d2

    # Calculate Hamming distance (number of bit differences)
    diff_bits = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(d1, d2))
    # For a 256-bit hash, expected bit flips should be well above 90 (typically ~128)
    assert diff_bits >= 90


def test_sha256_component_reordering_produces_different_digest():
    """Reordering salt, nonce, ciphertext produces a distinct digest."""
    c1 = b"SALT_VALUE_32_BYTES_LONG_0000000"
    c2 = b"NONCE_12_B"
    c3 = b"CIPHERTEXT_DATA"

    d1 = sha256_components(c1, c2, c3)
    d2 = sha256_components(c2, c1, c3)
    assert d1 != d2


# ─────────────────────────────────────────────────────────────────────────────
# 3. Payload Malformation & Defense
# ─────────────────────────────────────────────────────────────────────────────

def test_payload_invalid_json_rejected():
    with pytest.raises(PayloadError):
        parse_payload(b"{ invalid json syntax ...")


def test_payload_non_dict_json_rejected():
    with pytest.raises(PayloadError):
        parse_payload(b"[1, 2, 3, 4]")


def test_payload_unsupported_version_rejected():
    payload = {
        "version": 99,
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": 600000,
        "salt": "AAAA",
        "nonce": "AAAA",
        "ciphertext": "AAAA",
        "sha256": "0" * 64,
    }
    raw = json.dumps(payload).encode("utf-8")
    with pytest.raises(PayloadError, match="Unsupported payload version"):
        parse_payload(raw)


def test_payload_corrupted_base64_rejected():
    payload = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": 600000,
        "salt": "!!! Not Base64 !!!",
        "nonce": "AAAA",
        "ciphertext": "AAAA",
        "sha256": "a" * 64,
    }
    with pytest.raises(PayloadError):
        decode_payload_fields(payload)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Steganography Resource Exhaustion & OOM Defenses
# ─────────────────────────────────────────────────────────────────────────────

def test_header_spoofing_does_not_cause_oom():
    """An embedded header claiming 4 GB payload is caught before memory allocation."""
    img = Image.new("RGB", (30, 30), color=(50, 50, 50))
    arr = np.array(img, dtype=np.uint8).flatten()

    # Encode fake length: 4,000,000,000 bytes (0xEE6B2800)
    fake_len = struct.pack(">I", 4000000000)
    fake_len_bits = np.unpackbits(np.frombuffer(fake_len, dtype=np.uint8))
    arr[:32] = (arr[:32] & 0xFE) | fake_len_bits

    stego_fake = Image.fromarray(arr.reshape((30, 30, 3)), mode="RGB")
    with pytest.raises(ExtractionError):
        extract_payload(stego_fake)


def test_grayscale_image_handled_safely():
    """Grayscale images (mode L) are converted to RGB without crash."""
    gray_img = Image.new("L", (80, 80), color=128)
    payload = b"Grayscale stego test"
    stego = embed_payload(gray_img, payload)
    assert stego.mode == "RGB"
    assert extract_payload(stego) == payload


# ─────────────────────────────────────────────────────────────────────────────
# 5. Image Validation & Disallowed Format Security
# ─────────────────────────────────────────────────────────────────────────────

def test_webp_rejected():
    buf = io.BytesIO()
    img = Image.new("RGB", (50, 50), color=(100, 100, 100))
    img.save(buf, format="WEBP")
    with pytest.raises(ImageFormatError):
        validate_image_file(buf.getvalue(), "sample.webp")


def test_gif_rejected():
    buf = io.BytesIO()
    img = Image.new("RGB", (50, 50), color=(100, 100, 100))
    img.save(buf, format="GIF")
    with pytest.raises(ImageFormatError):
        validate_image_file(buf.getvalue(), "sample.gif")


def test_text_file_as_png_rejected():
    fake_png_data = b"Plain text disguised as a PNG file header."
    with pytest.raises(ImageContentError):
        validate_image_file(fake_png_data, "disguised.png")


def test_filename_with_spaces_and_unicode():
    safe_name = sanitize_filename("my secret 🔐 photo cover.png")
    assert " " not in safe_name or "_" in safe_name
    assert ".." not in safe_name


# ─────────────────────────────────────────────────────────────────────────────
# 6. Path Traversal Defenses (/download/ route)
# ─────────────────────────────────────────────────────────────────────────────

def test_download_nested_traversal_blocked(client):
    assert client.get("/download/....//....//app.py").status_code in (400, 404)
    assert client.get("/download/%2e%2e%2fapp.py").status_code in (400, 404)


# ─────────────────────────────────────────────────────────────────────────────
# 7. Session Privacy & Sensitive Data Leak Isolation
# ─────────────────────────────────────────────────────────────────────────────

def test_session_has_no_cryptographic_secrets(client):
    img_buf = _make_image_bytes("PNG", (120, 120))
    secret = "TopSecretMessage123"
    pwd = "UltraSecretPassword#99"

    with client.session_transaction() as sess:
        sess.clear()

    res = client.post("/hide", data={
        "image": (img_buf, "cover.png"),
        "message": secret,
        "password": pwd,
        "confirm_password": pwd,
    }, content_type="multipart/form-data")
    assert res.status_code == 200

    # Inspect session data
    with client.session_transaction() as sess:
        last_analysis = sess.get("last_analysis", {})
        # Verify no sensitive data in session
        assert secret not in str(sess)
        assert pwd not in str(sess)
        assert "key" not in last_analysis
        assert "password" not in last_analysis


# ─────────────────────────────────────────────────────────────────────────────
# 8. End-to-End Multi-Language & Tampering Detection
# ─────────────────────────────────────────────────────────────────────────────

def test_end_to_end_multilingual_roundtrip(client):
    multilingual = "Security Alert 🔐: नमस्ते दुनिया — こんにちは — Bonjour le monde 🛡️"
    passphrase = "MultiLingualPass#2026!"

    cover_buf = _make_image_bytes("PNG", (300, 300))

    hide_res = client.post("/hide", data={
        "image": (cover_buf, "intl_cover.png"),
        "message": multilingual,
        "password": passphrase,
        "confirm_password": passphrase,
    }, content_type="multipart/form-data")
    assert hide_res.status_code == 200

    match = re.search(r"stego_[a-f0-9]+\.png", hide_res.data.decode("utf-8"))
    assert match is not None
    stego_filename = match.group(0)

    dl_res = client.get(f"/download/{stego_filename}")
    assert dl_res.status_code == 200

    extract_res = client.post("/extract", data={
        "image": (io.BytesIO(dl_res.data), stego_filename),
        "password": passphrase,
    }, content_type="multipart/form-data")
    assert extract_res.status_code == 200
    assert multilingual.encode("utf-8") in extract_res.data


def test_tampered_stego_pixel_fails_safely_on_extract(client):
    cover_buf = _make_image_bytes("PNG", (200, 200))
    secret = "Confidential Report"
    passphrase = "CorrectPassword123"

    hide_res = client.post("/hide", data={
        "image": (cover_buf, "cover.png"),
        "message": secret,
        "password": passphrase,
        "confirm_password": passphrase,
    }, content_type="multipart/form-data")
    match = re.search(r"stego_[a-f0-9]+\.png", hide_res.data.decode("utf-8"))
    stego_filename = match.group(0)

    dl_res = client.get(f"/download/{stego_filename}")
    stego_img = Image.open(io.BytesIO(dl_res.data))
    arr = np.array(stego_img)

    # Flip 1 pixel in channel 0 (tampering)
    arr[0, 50, 0] ^= 1

    tampered_buf = io.BytesIO()
    Image.fromarray(arr).save(tampered_buf, format="PNG")
    tampered_buf.seek(0)

    # Extracting tampered image must fail safely and NEVER return plaintext
    extract_res = client.post("/extract", data={
        "image": (tampered_buf, "tampered.png"),
        "password": passphrase,
    }, content_type="multipart/form-data")
    assert extract_res.status_code == 400
    assert secret.encode("utf-8") not in extract_res.data
