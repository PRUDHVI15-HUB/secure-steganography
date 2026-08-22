"""
tests/test_image_analysis.py
─────────────────────────────
Automated tests for utils/image_analysis.py.

Tests cover:
  1. Identical images → MSE = 0.
  2. Identical images → PSNR = infinity.
  3. One-pixel / one-channel modification produces expected MSE.
  4. PSNR matches expected mathematical result.
  5. Different dimensions rejected.
  6. RGB/RGBA conversion handled correctly.
  7. Image information reports correct dimensions.
  8. Correct channel count.
  9. Capacity matches lsb.calculate_capacity().
  10. Payload utilization is correct.
  11. Zero capacity handled safely.
  12. Negative payload size rejected.

Run with:
    pytest tests/test_image_analysis.py -v
"""

import math
import numpy as np
from PIL import Image
import pytest

from steganography.lsb import calculate_capacity
from utils.image_analysis import (
    calculate_mse,
    calculate_psnr,
    analyze_image_difference,
    get_image_info,
    get_capacity_info,
    calculate_payload_utilization,
    AnalysisError,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1-2. Identical images → MSE = 0, PSNR = infinity
# ─────────────────────────────────────────────────────────────────────────────

def test_identical_images_mse_zero():
    img1 = Image.new("RGB", (50, 50), color=(100, 150, 200))
    img2 = Image.new("RGB", (50, 50), color=(100, 150, 200))
    assert calculate_mse(img1, img2) == 0.0


def test_identical_images_psnr_infinity():
    assert calculate_psnr(0.0) == float("inf")
    img1 = Image.new("RGB", (50, 50), color=(100, 150, 200))
    img2 = img1.copy()
    diff = analyze_image_difference(img1, img2)
    assert diff["mse"] == 0.0
    assert math.isinf(diff["psnr"])
    assert "identical" in diff["psnr_display"]


# ─────────────────────────────────────────────────────────────────────────────
# 3-4. Known mathematical MSE & PSNR verification
# ─────────────────────────────────────────────────────────────────────────────

def test_known_mse_calculation():
    # 2x2 image = 4 pixels = 12 total channel values
    # Modify exactly 1 channel of 1 pixel by +2
    # MSE = (2^2) / 12 = 4 / 12 = 1/3 ≈ 0.33333333
    arr1 = np.zeros((2, 2, 3), dtype=np.uint8)
    arr2 = np.zeros((2, 2, 3), dtype=np.uint8)
    arr2[0, 0, 0] = 2

    img1 = Image.fromarray(arr1, mode="RGB")
    img2 = Image.fromarray(arr2, mode="RGB")

    mse = calculate_mse(img1, img2)
    expected_mse = 4.0 / 12.0
    assert pytest.approx(mse, rel=1e-6) == expected_mse


def test_psnr_mathematical_formula():
    # PSNR = 10 * log10(255^2 / MSE)
    # If MSE = 1.0, PSNR = 10 * log10(65025) ≈ 48.1308036 dB
    mse = 1.0
    expected_psnr = 10.0 * math.log10(65025.0)
    assert pytest.approx(calculate_psnr(mse), rel=1e-6) == expected_psnr


def test_invalid_psnr_input():
    with pytest.raises(ValueError):
        calculate_psnr(-1.0)

    with pytest.raises(ValueError):
        calculate_psnr(float("nan"))


# ─────────────────────────────────────────────────────────────────────────────
# 5. Different dimensions rejected
# ─────────────────────────────────────────────────────────────────────────────

def test_dimension_mismatch_rejected():
    img1 = Image.new("RGB", (50, 50))
    img2 = Image.new("RGB", (50, 60))
    with pytest.raises(AnalysisError, match="dimensions must match"):
        calculate_mse(img1, img2)

    with pytest.raises(AnalysisError, match="dimensions must match"):
        analyze_image_difference(img1, img2)


# ─────────────────────────────────────────────────────────────────────────────
# 6. RGB/RGBA conversion handled correctly
# ─────────────────────────────────────────────────────────────────────────────

def test_rgba_rgb_comparison():
    # Comparing RGBA with RGB of same RGB channel values should give MSE = 0
    # because alpha channel is discarded on RGB conversion
    rgb = Image.new("RGB", (40, 40), color=(10, 20, 30))
    rgba = Image.new("RGBA", (40, 40), color=(10, 20, 30, 200))
    assert calculate_mse(rgb, rgba) == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# 7-8. Image information and channel count
# ─────────────────────────────────────────────────────────────────────────────

def test_get_image_info():
    img_rgb = Image.new("RGB", (1920, 1080))
    info_rgb = get_image_info(img_rgb, file_size=500000)
    assert info_rgb["width"] == 1920
    assert info_rgb["height"] == 1080
    assert info_rgb["channels"] == 3
    assert info_rgb["total_pixels"] == 1920 * 1080
    assert info_rgb["file_size_bytes"] == 500000
    assert info_rgb["file_size_kb"] == pytest.approx(488.28, rel=1e-2)

    img_rgba = Image.new("RGBA", (300, 200))
    info_rgba = get_image_info(img_rgba)
    assert info_rgba["channels"] == 4
    assert "file_size_bytes" not in info_rgba


# ─────────────────────────────────────────────────────────────────────────────
# 9. Capacity matches lsb.calculate_capacity()
# ─────────────────────────────────────────────────────────────────────────────

def test_get_capacity_info_delegates():
    img = Image.new("RGB", (200, 150))
    cap_info = get_capacity_info(img)
    expected_capacity = calculate_capacity(img)

    assert cap_info["width"] == 200
    assert cap_info["height"] == 150
    assert cap_info["channels"] == 3
    assert cap_info["total_pixels"] == 30000
    assert cap_info["embedding_bits"] == 30000 * 3
    assert cap_info["total_bytes"] == (30000 * 3) // 8
    assert cap_info["payload_capacity"] == expected_capacity


# ─────────────────────────────────────────────────────────────────────────────
# 10-12. Payload utilization
# ─────────────────────────────────────────────────────────────────────────────

def test_payload_utilization():
    # 500 bytes in 2000 bytes capacity = 25%
    util = calculate_payload_utilization(500, 2000)
    assert pytest.approx(util) == 25.0

    # 0 bytes = 0%
    assert calculate_payload_utilization(0, 1000) == 0.0


def test_payload_utilization_zero_capacity():
    # Division by zero safety
    assert calculate_payload_utilization(10, 0) == 0.0


def test_payload_utilization_negative_rejected():
    with pytest.raises(ValueError, match="non-negative"):
        calculate_payload_utilization(-5, 100)

    with pytest.raises(ValueError, match="non-negative"):
        calculate_payload_utilization(50, -10)
