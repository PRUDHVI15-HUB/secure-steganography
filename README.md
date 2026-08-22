# Secure Image Steganography

### *AES-256-GCM + SHA-256 + Spatial LSB Steganography*

A layered covert-communication and cryptographic integrity system developed as a laboratory project for **Cryptography and Network Security (CNS)**.

---

## 📑 Table of Contents

- [1. Academic Abstract](#1-academic-abstract)
- [2. Problem Statement & Objectives](#2-problem-statement--objectives)
- [3. System Architecture & Complete Pipeline](#3-system-architecture--complete-pipeline)
- [4. Cryptographic Design](#4-cryptographic-design)
  - [PBKDF2 Key Derivation](#pbkdf2-key-derivation)
  - [AES-256-GCM Authenticated Encryption](#aes-256-gcm-authenticated-encryption)
  - [SHA-256 Integrity Verification](#sha-256-integrity-verification)
- [5. Steganography Design & Payload Structure](#5-steganography-design--payload-structure)
  - [Spatial LSB Embedding Algorithm](#spatial-lsb-embedding-algorithm)
  - [Capacity Formula & PNG Requirement](#capacity-formula--png-requirement)
  - [Versioned JSON Payload Specification](#versioned-json-payload-specification)
- [6. Image Quality & Security Analysis](#6-image-quality--security-analysis)
- [7. Project Structure](#7-project-structure)
- [8. Installation & Execution Guide](#8-installation--execution-guide)
- [9. Step-by-Step Usage Guide](#9-step-by-step-usage-guide)
- [10. Automated Testing & Security Verification](#10-automated-testing--security-verification)
- [11. CNS Concepts Demonstrated](#11-cns-concepts-demonstrated)
- [12. Limitations & Future Enhancements](#12-limitations--future-enhancements)
- [13. Academic Note & License](#13-academic-note--license)

---

## 1. Academic Abstract

Traditional encryption renders data unintelligible to unauthorized parties, yet the visible presence of ciphertext can draw adversarial attention. Conversely, classical spatial steganography conceals the existence of communication within innocent cover media, but lacks defense if the embedding algorithm is identified. 

This project implements a dual-defense system integrating authenticated symmetric cryptography with spatial image steganography. Secret plaintext is encrypted using **AES-256-GCM** with keys derived via **PBKDF2-HMAC-SHA256** (600,000 iterations, 32-byte cryptographic salt). A **SHA-256** digest over cryptographic components $(salt \parallel nonce \parallel ciphertext)$ enables pre-decryption container verification. The resulting versioned JSON payload is embedded into lossless RGB image channels using **Least Significant Bit (LSB)** spatial replacement preceded by a 4-byte big-endian length header. Objective image degradation is evaluated via Mean Squared Error (MSE) and Peak Signal-to-Noise Ratio (PSNR).

---

## 2. Problem Statement & Objectives

### Problem Statement
Transmitting plain ciphertext over monitored channels signals the presence of sensitive exchanges, increasing intercept risk. Standard LSB steganography without cryptographic protection exposes plain messages if extracted by third parties.

### Objectives
1. **Confidentiality:** Protect message contents against unauthorized access using AES-256-GCM authenticated encryption.
2. **Concealment:** Embed encrypted payloads invisibly into lossless image carriers using spatial LSB manipulation.
3. **Integrity & Authentication:** Verify payload structural integrity via SHA-256 hashing and ensure ciphertext authenticity via 16-byte GCM tags.
4. **Visual Imperceptibility:** Maintain high reconstruction fidelity ($PSNR \gg 40\text{ dB}$, low MSE).
5. **Defensive Web Architecture:** Provide a hardened Flask interface with strict format validation, path traversal defense, and session privacy.

---

## 3. System Architecture & Complete Pipeline

```
[ HIDE WORKFLOW ]
Plaintext Message + Passphrase
       │
       ▼
[PBKDF2-HMAC-SHA256] ──► 256-bit Key (600k iterations, 32B Salt)
       │
       ▼
[AES-256-GCM Encrypt] ──► Ciphertext + 16B GCM Authentication Tag (12B Nonce)
       │
       ▼
[SHA-256 Hash] ────────► 256-bit Digest over (Salt || Nonce || Ciphertext)
       │
       ▼
[Payload Builder] ─────► Versioned JSON (v1) Base64 Serialized Bytes
       │
       ▼
[Spatial LSB Embed] ───► [4-byte Big-Endian Length] + [Payload Bits] into Cover Image
       │
       ▼
Stego PNG Output ──────► MSE / PSNR Quality Evaluation + Secure Download

─────────────────────────────────────────────────────────────────────────────

[ EXTRACT WORKFLOW ]
Stego PNG Image + Passphrase
       │
       ▼
[Spatial LSB Extract] ─► Read 32-bit Header Length ──► Extract Payload Bytes
       │
       ▼
[Payload Parser] ──────► Parse JSON v1 ──► Decode Base64 Parameters
       │
       ▼
[SHA-256 Verify] ──────► Constant-time verification of container hash
       │
       ▼
[PBKDF2-HMAC-SHA256] ──► Re-derive 256-bit Key from Password + Salt
       │
       ▼
[AES-256-GCM Decrypt] ─► Verify GCM Tag & Decrypt Ciphertext
       │
       ▼
Recovered Plaintext Message
```

---

## 4. Cryptographic Design

### PBKDF2 Key Derivation
- **Algorithm:** PBKDF2-HMAC-SHA256
- **Salt:** 32 bytes (256 bits) cryptographically random (`os.urandom`) generated per operation.
- **Iterations:** 600,000 rounds.
- **Derived Output:** 32-byte (256-bit) symmetric key.
- **Rationale:** Protects against dictionary and precomputed rainbow-table attacks by imposing computational work on key derivation.

### AES-256-GCM Authenticated Encryption
- **Cipher:** Advanced Encryption Standard in Galois/Counter Mode (AES-256-GCM).
- **Nonce / IV:** 12 bytes (96 bits) unique random nonce per encryption (`os.urandom`).
- **Authentication Tag:** 16 bytes (128 bits) appended to the raw ciphertext.
- **Security Properties:** Provides **confidentiality** and **authenticity**. Any modification to the ciphertext or authentication tag triggers immediate decryption rejection (`DecryptionError`).

### SHA-256 Integrity Verification
- **Digest Construction:** Sequential digest over binary components:
  $$\text{Digest} = \text{SHA-256}(\text{salt} \parallel \text{nonce} \parallel \text{ciphertext})$$
- **Verification:** Evaluated during extraction using constant-time comparison (`hmac.compare_digest`) before attempting cryptographic decryption.
- *Distinction:* SHA-256 demonstrates structural integrity and hashing concepts; cryptographic authenticity is enforced by the AES-GCM tag.

---

## 5. Steganography Design & Payload Structure

### Spatial LSB Embedding Algorithm
1. The cover image is verified and converted to an RGB NumPy array ($\text{uint8}$).
2. The payload byte string is prefixed with a **4-byte big-endian unsigned integer** representing its exact length:
   $$\text{Header} = \text{struct.pack}(">I", \text{len}(\text{payload}))$$
3. Each bit of the header and payload is mapped sequentially to the least significant bit (LSB) of each RGB channel:
   $$\text{Pixel}' = (\text{Pixel} \ \& \ 0\text{xFE}) \ | \ \text{bit}$$
4. The modified pixel grid is saved losslessly as a PNG image.

### Capacity Formula & PNG Requirement
- **Total Available Bits:** $W \times H \times 3$ (1 bit per color channel).
- **Usable Payload Capacity:**
  $$\text{Capacity (Bytes)} = \left\lfloor \frac{W \times H \times 3}{8} \right\rfloor - 4$$
- **Lossless Constraint:** PNG or BMP formats are strictly required. Lossy formats (JPEG/WebP) perform discrete cosine transform (DCT) quantization and spatial compression that corrupt individual pixel LSBs, destroying embedded payloads.

### Versioned JSON Payload Specification
The embedded byte stream consists of a canonical, compact UTF-8 JSON document:

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "kdf": "PBKDF2-HMAC-SHA256",
  "iterations": 600000,
  "salt": "<Base64 encoded 32-byte salt>",
  "nonce": "<Base64 encoded 12-byte nonce>",
  "ciphertext": "<Base64 encoded (ciphertext + 16B GCM tag)>",
  "sha256": "<64-character lowercase hexadecimal hash>"
}
```

---

## 6. Image Quality & Security Analysis

The application computes objective image quality metrics comparing the original cover image ($I_1$) and stego image ($I_2$) across dimensions $W \times H$ and 3 color channels:

### Mean Squared Error (MSE)
$$\text{MSE} = \frac{1}{3 \cdot W \cdot H} \sum_{c=1}^{3} \sum_{x=0}^{W-1} \sum_{y=0}^{H-1} \left( I_1(x,y,c) - I_2(x,y,c) \right)^2$$

### Peak Signal-to-Noise Ratio (PSNR)
$$\text{PSNR} = 10 \cdot \log_{10}\left( \frac{255^2}{\text{MSE}} \right) \quad (\text{dB})$$
- If $\text{MSE} = 0$, $\text{PSNR} = \infty$ (identical images).
- For spatial 1-bit LSB steganography, PSNR typically exceeds $50\text{ dB}$, confirming high visual imperceptibility.

### Payload Utilization Percentage
$$\text{Utilization} = \left( \frac{\text{Payload Size (Bytes)}}{\text{Payload Capacity (Bytes)}} \right) \times 100\%$$

---

## 7. Project Structure

```
secure-steganography/
├── app.py                     # Flask application factory, error handlers & download route
├── requirements.txt           # Python dependencies (Flask, cryptography, Pillow, numpy, pytest)
├── config/
│   ├── __init__.py
│   └── settings.py            # Configuration settings (file limits, runtime paths, PBKDF2 parameters)
├── crypto/
│   ├── __init__.py
│   ├── encryption.py          # PBKDF2-HMAC-SHA256 & AES-256-GCM implementation
│   └── hashing.py             # SHA-256 utility & component hashing functions
├── steganography/
│   ├── __init__.py
│   └── lsb.py                 # Spatial 1-bit RGB LSB embedding & extraction module
├── utils/
│   ├── __init__.py
│   ├── payload.py             # Versioned JSON payload builder, serializer, and parser
│   ├── validators.py          # File format, MIME magic-byte, size & capacity validators
│   └── image_analysis.py      # MSE, PSNR, capacity info & utilization calculation
├── routes/
│   ├── __init__.py            # Blueprint registration entry point
│   ├── hide.py                # /hide route (encryption + LSB embedding pipeline)
│   ├── extract.py             # /extract route (LSB extraction + authentication pipeline)
│   └── analysis.py           # /analysis route (security metrics & on-demand comparator)
├── templates/
│   ├── base.html              # Base layout with navbar, alerts, and cybersecurity footer
│   ├── index.html             # Dashboard homepage with technology pillars and pipeline
│   ├── hide.html              # Two-column hide form with dropzone, preview, & capacity meter
│   ├── extract.html           # Stego extraction form with copy-to-clipboard & verification badges
│   ├── analysis.html          # Security metric KPI dashboard and on-demand comparator
│   └── about.html             # Comprehensive educational reference and CNS architecture guide
├── static/
│   ├── css/
│   │   └── style.css          # Dark cybersecurity UI design system & responsive layout
│   └── js/
│       └── main.js            # Hardened vanilla JS for preview, capacity estimation, & A11y
├── uploads/                   # Temporary directory for uploaded files
├── outputs/                   # Directory for generated stego PNG files
└── tests/
    ├── test_crypto.py         # 19 tests: AES-GCM, PBKDF2, error conditions
    ├── test_hashing.py        # 25 tests: SHA-256 hashing, avalanche, constant-time compare
    ├── test_payload.py        # 53 tests: JSON schema, Base64 serialization, validation
    ├── test_steganography.py  # 39 tests: Spatial LSB embedding, extraction, header limits
    ├── test_validators.py     # 17 tests: Image format, magic bytes, file size, sanitation
    ├── test_image_analysis.py # 14 tests: MSE, PSNR formulas, capacity mathematics
    ├── test_routes.py         # 22 tests: Integration & route endpoints
    └── test_security_audit.py # 22 tests: Security failures, OOM defenses, session privacy
```

---

## 8. Installation & Execution Guide

### Prerequisites
- **Python:** Version 3.10, 3.11, or 3.12 (Tested on Python 3.11.9).
- **Operating System:** Windows, Linux, or macOS.

### Setup Instructions (Windows)

1. **Clone or Open the Repository:**
   ```powershell
   cd "C:\Users\USER\Desktop\CNS LAB PROJECT\secure-steganography"
   ```

2. **Create and Activate a Virtual Environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Install Required Dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Launch the Flask Application:**
   ```powershell
   python app.py
   ```

5. **Access the Web Dashboard:**
   Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## 9. Step-by-Step Usage Guide

### A. Hiding a Secret Message
1. Open the **Hide Message** page (`/hide`).
2. Select or drag-and-drop a valid cover image (**PNG** or **BMP**).
3. Enter your confidential text in the **Secret Message** field (live UTF-8 byte counter updates in real time).
4. Enter and confirm your passphrase (the capacity meter confirms payload safety).
5. Click **Encrypt & Hide Message**.
6. Review the calculated MSE, PSNR, and SHA-256 hash on the result card.
7. Click **Download Stego PNG** to save the generated image.

### B. Extracting a Hidden Message
1. Open the **Extract Message** page (`/extract`).
2. Upload the generated stego PNG image.
3. Enter the exact passphrase used during encryption.
4. Click **Extract & Decrypt Message**.
5. The system verifies the container SHA-256 hash, authenticates the AES-GCM tag, and displays the recovered plaintext message.
6. Click **Copy Message** to copy the plaintext to your clipboard.

### C. Viewing Quality & Parameter Analysis
1. Open the **Analysis** page (`/analysis`).
2. View the performance metrics from the most recent hide operation.
3. Use the **On-Demand Cover vs Stego Comparison** form to upload original and modified images to calculate instantaneous MSE and PSNR values.

---

## 10. Automated Testing & Security Verification

The project includes an automated test suite across 8 dedicated test modules:

```powershell
# Run the complete test suite
python -m pytest tests/ -v
```

### Test Suite Summary

| Test Module | Coverage Area | Tests | Result |
|---|---|:---:|:---:|
| `test_crypto.py` | PBKDF2 derivation, AES-256-GCM, tag tampering, wrong password | 19 | ✅ Passed |
| `test_hashing.py` | SHA-256 component hashing, avalanche effect, constant-time compare | 25 | ✅ Passed |
| `test_payload.py` | Versioned JSON schema, Base64 encoding/decoding, malformed data | 53 | ✅ Passed |
| `test_steganography.py` | Spatial LSB embedding/extraction, header encoding, memory bounds | 39 | ✅ Passed |
| `test_validators.py` | Magic bytes check, format validation, size limits, safe filenames | 17 | ✅ Passed |
| `test_image_analysis.py` | MSE and PSNR mathematical validation, capacity allocation | 14 | ✅ Passed |
| `test_routes.py` | Flask route endpoints, download security, integration pipelines | 22 | ✅ Passed |
| `test_security_audit.py` | OOM defense, session privacy, path traversal, multilingual E2E | 22 | ✅ Passed |
| **Total** | **Complete System Verification** | **211** | **211 Passed (0 Failed)** |

---

## 11. CNS Concepts Demonstrated

| CNS Concept | System Implementation |
|---|---|
| **Confidentiality** | AES-256-GCM symmetric encryption prevents plaintext exposure without the key. |
| **Key Derivation** | PBKDF2-HMAC-SHA256 with 600,000 iterations transforms passwords into strong 256-bit keys. |
| **Data Integrity** | SHA-256 digest over $(salt \parallel nonce \parallel ciphertext)$ verifies container structural integrity. |
| **Authentication** | AES-GCM 16-byte authentication tag guarantees ciphertext authenticity and prevents tampering. |
| **Steganography** | Spatial 1-bit RGB LSB embedding hides data existence within natural image noise. |
| **Semantic Security (IND-CPA)** | Fresh 32-byte salt and 12-byte nonce ensure identical messages produce distinct ciphertexts. |
| **Constant-Time Verification** | `hmac.compare_digest` prevents timing side-channel attacks during hash checks. |
| **Web & File Security** | Strict magic-byte format validation, path traversal defense, and session privacy. |

---

## 12. Limitations & Future Enhancements

### Known Limitations
1. **Spatial LSB Fragility:** Lossy image operations (JPEG recompression, social media image filters, resizing) alter least significant bits and destroy the embedded payload.
2. **Dimension-Dependent Capacity:** Embedding capacity is strictly bounded by image resolution ($\approx 3\text{ bits per pixel} - 32\text{ header bits}$).
3. **Statistical Steganalysis:** Standard spatial LSB replacement can be detected by targeted statistical steganalysis (e.g., Chi-square, Sample Pairs Analysis).
4. **Lossless Formats Only:** Restricted to lossless container formats (PNG and BMP).

### Future Enhancements
- **Adaptive Steganography:** Embed data in high-variance/edge regions (e.g., using edge detection filters) to increase steganalysis resistance.
- **Permuted / Keyed Embedding:** Use a pseudo-random number generator (PRNG) seeded with a stego-key to scatter bit positions non-sequentially across the pixel grid.
- **Frequency Domain Steganography:** Implement DCT or Discrete Wavelet Transform (DWT) embedding for higher robustness against minor image transformations.
- **Public-Key Cryptography:** Support asymmetric key exchange (e.g., RSA or ECC) for multi-party key distribution.

---

## 13. Academic Note & License

This project was developed for academic evaluation in the **Cryptography and Network Security (CNS)** course. It is intended for educational demonstration of layered security principles.

- **Author:** CNS Laboratory Project Team
- **Course:** Cryptography and Network Security (CS401 / CNS Lab)
- **License:** Open for academic and educational evaluation.
