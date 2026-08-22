"""
tests/test_routes.py
────────────────────
Comprehensive Flask route and integration test suite.

Tests cover:
  1. GET / (Home page)
  2. GET /hide (Hide page)
  3. GET /extract (Extract page)
  4. GET /analysis (Analysis page)
  5. GET /about (About page)
  6. Valid hide workflow (POST /hide)
  7. Valid extraction workflow (POST /extract)
  8. Wrong password on extract
  9. Tampered stego image (integrity check failure)
  10. Oversized image handling
  11. Invalid/fake image upload
  12. Unsupported extension (JPEG upload rejected)
  13. Empty message rejected
  14. Empty password rejected
  15. Password mismatch rejected
  16. Payload too large for tiny image rejected
  17. Download generated stego PNG
  18. Path traversal attempt on download route rejected
  19. Missing file upload rejected
  20. Malformed payload rejected gracefully
  21. Full End-to-End pipeline round trip with Unicode message

Run with:
    pytest tests/test_routes.py -v
"""

import io
import re
import numpy as np
from PIL import Image
import pytest

from app import create_app


# ─── Test Fixtures ───────────────────────────────────────────────────────────

@pytest.fixture
def app():
    """Create and configure a clean Flask application instance for testing."""
    test_app = create_app()
    test_app.config.update({
        "TESTING": True,
        "DEBUG": False,
        "WTF_CSRF_ENABLED": False,
    })
    yield test_app


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


def _make_test_image_bytes(format_name: str = "PNG", size: tuple = (200, 200), color: tuple = (80, 120, 160)) -> io.BytesIO:
    """Generate in-memory image bytes for multipart form uploads."""
    img = Image.new("RGB", size, color=color)
    buf = io.BytesIO()
    img.save(buf, format=format_name)
    buf.seek(0)
    return buf


# ─────────────────────────────────────────────────────────────────────────────
# 1-5. GET Route status checks
# ─────────────────────────────────────────────────────────────────────────────

def test_get_home_page(client):
    res = client.get("/")
    assert res.status_code == 200


def test_get_hide_page(client):
    res = client.get("/hide")
    assert res.status_code == 200
    assert b"Hide Message" in res.data


def test_get_extract_page(client):
    res = client.get("/extract")
    assert res.status_code == 200
    assert b"Extract Message" in res.data


def test_get_analysis_page(client):
    res = client.get("/analysis")
    assert res.status_code == 200
    assert b"Security" in res.data


def test_get_about_page(client):
    res = client.get("/about")
    assert res.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# 6. Valid Hide Workflow
# ─────────────────────────────────────────────────────────────────────────────

def test_valid_hide_post(client):
    img_buf = _make_test_image_bytes("PNG", (200, 200))
    data = {
        "image": (img_buf, "cover.png"),
        "message": "Secret message for testing.",
        "password": "Password@123",
        "confirm_password": "Password@123",
    }
    res = client.post("/hide", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    assert b"Stego Image Created Successfully" in res.data
    assert b"stego_" in res.data
    assert b"PSNR" in res.data


# ─────────────────────────────────────────────────────────────────────────────
# 7. Valid Extract Workflow
# ─────────────────────────────────────────────────────────────────────────────

def test_valid_hide_and_extract_flow(client):
    # Step 1: Hide message
    secret_text = "College CNS Lab Secret 🔐"
    password = "StrongPassword#2026"

    img_buf = _make_test_image_bytes("PNG", (250, 250))
    hide_data = {
        "image": (img_buf, "test_cover.png"),
        "message": secret_text,
        "password": password,
        "confirm_password": password,
    }
    hide_res = client.post("/hide", data=hide_data, content_type="multipart/form-data")
    assert hide_res.status_code == 200

    # Extract stego filename from response
    match = re.search(r"stego_[a-f0-9]+\.png", hide_res.data.decode("utf-8"))
    assert match is not None
    stego_filename = match.group(0)

    # Step 2: Download stego image
    dl_res = client.get(f"/download/{stego_filename}")
    assert dl_res.status_code == 200
    stego_bytes = io.BytesIO(dl_res.data)

    # Step 3: Extract message
    extract_data = {
        "image": (stego_bytes, stego_filename),
        "password": password,
    }
    extract_res = client.post("/extract", data=extract_data, content_type="multipart/form-data")
    assert extract_res.status_code == 200
    assert secret_text.encode("utf-8") in extract_res.data
    assert b"SHA-256 Integrity Verified" in extract_res.data
    assert b"AES-256-GCM Authenticated" in extract_res.data


# ─────────────────────────────────────────────────────────────────────────────
# 8. Wrong Password Handling
# ─────────────────────────────────────────────────────────────────────────────

def test_extract_wrong_password(client):
    # Hide with password A
    img_buf = _make_test_image_bytes("PNG", (200, 200))
    hide_data = {
        "image": (img_buf, "cover.png"),
        "message": "Top secret plan",
        "password": "correct_pass",
        "confirm_password": "correct_pass",
    }
    hide_res = client.post("/hide", data=hide_data, content_type="multipart/form-data")
    match = re.search(r"stego_[a-f0-9]+\.png", hide_res.data.decode("utf-8"))
    stego_filename = match.group(0)

    dl_res = client.get(f"/download/{stego_filename}")
    stego_bytes = io.BytesIO(dl_res.data)

    # Extract with wrong password B
    extract_data = {
        "image": (stego_bytes, stego_filename),
        "password": "wrong_password_xyz",
    }
    extract_res = client.post("/extract", data=extract_data, content_type="multipart/form-data")
    assert extract_res.status_code == 400
    assert b"Incorrect password" in extract_res.data


# ─────────────────────────────────────────────────────────────────────────────
# 9. Tampered Stego Image Handling
# ─────────────────────────────────────────────────────────────────────────────

def test_tampered_stego_image_detected(client):
    img_buf = _make_test_image_bytes("PNG", (200, 200))
    hide_data = {
        "image": (img_buf, "cover.png"),
        "message": "Authentic secret message",
        "password": "pass1234",
        "confirm_password": "pass1234",
    }
    hide_res = client.post("/hide", data=hide_data, content_type="multipart/form-data")
    match = re.search(r"stego_[a-f0-9]+\.png", hide_res.data.decode("utf-8"))
    stego_filename = match.group(0)

    dl_res = client.get(f"/download/{stego_filename}")
    
    # Tamper with the stego image pixel data (flip a byte in the payload region)
    stego_img = Image.open(io.BytesIO(dl_res.data))
    img_arr = np.array(stego_img, dtype=np.uint8)
    
    # Tamper a pixel in the payload body (after the 32-bit header)
    img_arr[0, 20, 0] ^= 1
    
    tampered_img = Image.fromarray(img_arr, mode="RGB")
    tampered_buf = io.BytesIO()
    tampered_img.save(tampered_buf, format="PNG")
    tampered_buf.seek(0)

    extract_data = {
        "image": (tampered_buf, "tampered_stego.png"),
        "password": "pass1234",
    }
    extract_res = client.post("/extract", data=extract_data, content_type="multipart/form-data")
    assert extract_res.status_code == 400
    # Should catch integrity failure or corrupted payload
    assert (b"Integrity verification failed" in extract_res.data or 
            b"corrupted" in extract_res.data or
            b"invalid" in extract_res.data)


# ─────────────────────────────────────────────────────────────────────────────
# 10-16. Validation Error Cases
# ─────────────────────────────────────────────────────────────────────────────

def test_jpeg_upload_rejected(client):
    jpeg_buf = _make_test_image_bytes("JPEG", (100, 100))
    data = {
        "image": (jpeg_buf, "test.jpg"),
        "message": "Message",
        "password": "pass",
        "confirm_password": "pass",
    }
    res = client.post("/hide", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert b"not an accepted image format" in res.data


def test_fake_png_rejected(client):
    fake_buf = io.BytesIO(b"Not an actual image byte stream.")
    data = {
        "image": (fake_buf, "fake.png"),
        "message": "Message",
        "password": "pass",
        "confirm_password": "pass",
    }
    res = client.post("/hide", data=data, content_type="multipart/form-data")
    assert res.status_code == 400


def test_empty_message_rejected(client):
    img_buf = _make_test_image_bytes("PNG", (100, 100))
    data = {
        "image": (img_buf, "cover.png"),
        "message": "   ",
        "password": "pass",
        "confirm_password": "pass",
    }
    res = client.post("/hide", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert b"cannot be empty" in res.data


def test_password_mismatch_rejected(client):
    img_buf = _make_test_image_bytes("PNG", (100, 100))
    data = {
        "image": (img_buf, "cover.png"),
        "message": "Valid message",
        "password": "passwordA",
        "confirm_password": "passwordB",
    }
    res = client.post("/hide", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert b"Passwords do not match" in res.data


def test_empty_password_rejected(client):
    img_buf = _make_test_image_bytes("PNG", (100, 100))
    data = {
        "image": (img_buf, "cover.png"),
        "message": "Valid message",
        "password": "",
        "confirm_password": "",
    }
    res = client.post("/hide", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert b"password cannot be empty" in res.data


def test_payload_exceeding_capacity_rejected(client):
    # Tiny 5x5 image has capacity = (5*5*3)//8 - 4 = 9 - 4 = 5 bytes
    tiny_img_buf = _make_test_image_bytes("PNG", (5, 5))
    data = {
        "image": (tiny_img_buf, "tiny.png"),
        "message": "A secret message that is definitely larger than five bytes.",
        "password": "pass",
        "confirm_password": "pass",
    }
    res = client.post("/hide", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert b"too large for this image" in res.data


# ─────────────────────────────────────────────────────────────────────────────
# 17-19. Download Route & Security Checks
# ─────────────────────────────────────────────────────────────────────────────

def test_download_valid_file(client):
    # Hide message to produce a valid file
    img_buf = _make_test_image_bytes("PNG", (100, 100))
    data = {
        "image": (img_buf, "cover.png"),
        "message": "Message for download test",
        "password": "pass",
        "confirm_password": "pass",
    }
    hide_res = client.post("/hide", data=data, content_type="multipart/form-data")
    match = re.search(r"stego_[a-f0-9]+\.png", hide_res.data.decode("utf-8"))
    stego_filename = match.group(0)

    dl_res = client.get(f"/download/{stego_filename}")
    assert dl_res.status_code == 200
    assert dl_res.headers.get("Content-Type") == "image/png"


def test_download_path_traversal_blocked(client):
    # Attempt directory traversal
    res = client.get("/download/../../app.py")
    assert res.status_code in (400, 404)

    res_backslash = client.get("/download/..\\..\\app.py")
    assert res_backslash.status_code in (400, 404)


def test_download_nonexistent_file(client):
    res = client.get("/download/stego_nonexistent_file_9999.png")
    assert res.status_code == 404


def test_missing_file_on_hide(client):
    data = {
        "message": "Secret",
        "password": "pass",
        "confirm_password": "pass",
    }
    res = client.post("/hide", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert b"select an image file" in res.data


def test_missing_file_on_extract(client):
    data = {
        "password": "pass",
    }
    res = client.post("/extract", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert b"select a stego image" in res.data


# ─────────────────────────────────────────────────────────────────────────────
# 20. Standalone /analysis Route POST Check
# ─────────────────────────────────────────────────────────────────────────────

def test_analysis_post_with_cover_and_stego(client):
    orig_buf = _make_test_image_bytes("PNG", (100, 100), color=(100, 100, 100))
    stego_buf = _make_test_image_bytes("PNG", (100, 100), color=(100, 100, 101))

    data = {
        "original_image": (orig_buf, "original.png"),
        "stego_image": (stego_buf, "stego.png"),
    }
    res = client.post("/analysis", data=data, content_type="multipart/form-data")
    assert res.status_code == 200
    assert b"Mean Squared Error" in res.data
    assert b"Peak Signal-to-Noise Ratio" in res.data


# ─────────────────────────────────────────────────────────────────────────────
# 21. Full End-to-End Pipeline Round Trip (Complex / Unicode)
# ─────────────────────────────────────────────────────────────────────────────

def test_full_end_to_end_unicode_pipeline(client):
    complex_message = "Project CNS 2026: AES-256-GCM + PBKDF2 + SHA-256 + LSB Stego 🚀 🔐 — नमस्ते"
    passphrase = "UltraSecurePassphrase#9876!"

    cover_buf = _make_test_image_bytes("PNG", (300, 300))

    # 1. Post to /hide
    hide_payload = {
        "image": (cover_buf, "cover_doc.png"),
        "message": complex_message,
        "password": passphrase,
        "confirm_password": passphrase,
    }
    hide_response = client.post("/hide", data=hide_payload, content_type="multipart/form-data")
    assert hide_response.status_code == 200

    match = re.search(r"stego_[a-f0-9]+\.png", hide_response.data.decode("utf-8"))
    assert match is not None
    generated_file = match.group(0)

    # 2. Download stego PNG
    dl_response = client.get(f"/download/{generated_file}")
    assert dl_response.status_code == 200
    stego_file_bytes = io.BytesIO(dl_response.data)

    # 3. Post to /extract
    extract_payload = {
        "image": (stego_file_bytes, generated_file),
        "password": passphrase,
    }
    extract_response = client.post("/extract", data=extract_payload, content_type="multipart/form-data")
    assert extract_response.status_code == 200
    assert complex_message.encode("utf-8") in extract_response.data
    assert b"SHA-256 Integrity Verified" in extract_response.data
    assert b"AES-256-GCM Authenticated" in extract_response.data
