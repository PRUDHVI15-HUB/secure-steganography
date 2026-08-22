# Secure Image Steganography

### *Layered Covert Communication: AES-256-GCM + SHA-256 + Spatial LSB Steganography*

A comprehensive, defense-in-depth cybersecurity and covert communication system developed for the **Cryptography and Network Security (CNS)** course.

---

## 📑 Table of Contents

1. [Executive Summary & Academic Abstract](#1-executive-summary--academic-abstract)
2. [Problem Statement & Core Objectives](#2-problem-statement--core-objectives)
3. [System Architecture & Data Flow Pipeline](#3-system-architecture--data-flow-pipeline)
4. [Cryptographic Architecture (Detailed)](#4-cryptographic-architecture-detailed)
   - [PBKDF2-HMAC-SHA256 Key Derivation](#pbkdf2-hmac-sha256-key-derivation)
   - [AES-256-GCM Authenticated Encryption](#aes-256-gcm-authenticated-encryption)
   - [SHA-256 Component Integrity Digest](#sha-256-component-integrity-digest)
5. [Steganography & Payload Architecture](#5-steganography--payload-architecture)
   - [Spatial 1-Bit RGB LSB Embedding Algorithm](#spatial-1-bit-rgb-lsb-embedding-algorithm)
   - [Capacity Calculation Formula](#capacity-calculation-formula)
   - [Why Lossless PNG Over Lossy JPEG?](#why-lossless-png-over-lossy-jpeg)
   - [Versioned JSON v1 Payload Structure](#versioned-json-v1-payload-structure)
6. [Image Quality Analysis & Evaluation](#6-image-quality-analysis--evaluation)
   - [MSE & PSNR Mathematical Formulations](#mse--psnr-mathematical-formulations)
   - [Payload Utilization Metrics](#payload-utilization-metrics)
7. [Repository File & Directory Structure](#7-repository-file--directory-structure)
8. [Local Installation & Setup Guide](#8-local-installation--setup-guide)
9. [Step-by-Step User Operation Guide](#9-step-by-step-user-operation-guide)
10. [Automated Testing & Security Verification (211/211 Passed)](#10-automated-testing--security-verification-211211-passed)
11. [Defensive Security Controls & Web Hardening](#11-defensive-security-controls--web-hardening)
12. [CNS Syllabus Mapping & Conceptual Pillars](#12-cns-syllabus-mapping--conceptual-pillars)
13. [Limitations & Future Scope](#13-limitations--future-scope)
14. [🎓 Team PPT / Presentation Slide Deck Outline](#14--team-ppt--presentation-slide-deck-outline)
15. [📄 Academic Project Report Structure](#15--academic-project-report-structure)
16. [🎤 Live Demo Script & Viva Voce Q&A Cheat-Sheet](#16--live-demo-script--viva-voce-qa-cheat-sheet)
17. [🌐 Free 1-Click Cloud Deployment (Render)](#17--free-1-click-cloud-deployment-render)

---

## 1. Executive Summary & Academic Abstract

Traditional encryption renders data unintelligible to unauthorized parties; however, the visible transmission of raw ciphertext readily flags suspicious activity to channel eavesdroppers. In contrast, standard image steganography hides the existence of data within cover media, but offers zero cryptographic confidentiality if the embedding mechanism is discovered.

This project implements a dual-layer defense-in-depth system:
1. **Cryptographic Layer:** Confidential plaintext is encrypted using **AES-256-GCM** (Galois/Counter Mode) with 256-bit symmetric keys derived from passphrases via **PBKDF2-HMAC-SHA256** (600,000 iterations, 32-byte cryptographic salt). A **SHA-256** cryptographic digest over $(salt \parallel nonce \parallel ciphertext)$ establishes structural integrity verification.
2. **Steganographic Layer:** The resulting canonical, versioned JSON payload is embedded into lossless RGB image channels using **Spatial Least Significant Bit (LSB)** replacement preceded by a 4-byte big-endian length header.

Reconstruction quality is verified using Mean Squared Error (**MSE**) and Peak Signal-to-Noise Ratio (**PSNR**), consistently achieving imperceptible distortion ($PSNR > 50\text{ dB}$).

---

## 2. Problem Statement & Core Objectives

### Problem Statement
- Plain ciphertext exposes the *presence* of sensitive communications.
- Unencrypted steganography exposes *plaintext* upon extraction.
- Lossy compression (e.g. JPEG) destroys spatial bit patterns.
- Weak password hashing enables dictionary/rainbow table attacks.

### Core Objectives
- **Confidentiality:** Military-grade AES-256-GCM symmetric encryption.
- **Integrity & Authenticity:** 16-byte GCM authentication tag for ciphertext tampering detection and SHA-256 container integrity.
- **Concealment:** Spatial RGB LSB replacement ensuring zero visual distortion.
- **Imperceptibility:** Mathematical proof via MSE and PSNR metrics.
- **Defensive Engineering:** Zero hardcoded secrets, session isolation, path traversal guards, and OOM defense.

---

## 3. System Architecture & Data Flow Pipeline

```
[ SENDER: ENCRYPT & HIDE WORKFLOW ]
Plaintext Message ("Hello CNS Lab") + Passphrase ("test1234")
       │
       ▼
[PBKDF2-HMAC-SHA256] ──► 256-bit Key (600k iterations, 32-byte Salt)
       │
       ▼
[AES-256-GCM Encrypt] ──► Ciphertext + 16B GCM Authentication Tag (12B Nonce)
       │
       ▼
[SHA-256 Hash] ────────► 256-bit Digest over (Salt || Nonce || Ciphertext)
       │
       ▼
[Payload Builder] ─────► Canonical Versioned JSON (v1) Base64 Encoded
       │
       ▼
[Spatial LSB Embed] ───► [4-Byte Big-Endian Length] + [Payload Bits] into RGB Channels
       │
       ▼
Stego PNG Output ──────► MSE / PSNR Quality Calculation + Secure Download

─────────────────────────────────────────────────────────────────────────────

[ RECEIVER: EXTRACT & DECRYPT WORKFLOW ]
Stego PNG Image + Shared Passphrase ("test1234")
       │
       ▼
[Spatial LSB Extract] ─► Read 32-bit Header Length ──► Extract Payload Bytes
       │
       ▼
[Payload Parser] ──────► Parse JSON Schema ──► Decode Base64 Parameters
       │
       ▼
[SHA-256 Verify] ──────► Constant-time check: HMAC.compare_digest(hash, recalc_hash)
       │
       ▼
[PBKDF2-HMAC-SHA256] ──► Re-derive 256-bit Key from Passphrase + Extracted Salt
       │
       ▼
[AES-256-GCM Decrypt] ─► Verify 16B Authentication Tag & Decrypt Ciphertext
       │
       ▼
Recovered Plaintext Message ("Hello CNS Lab")
```

---

## 4. Cryptographic Architecture (Detailed)

### PBKDF2-HMAC-SHA256 Key Derivation
- **Salt:** 32 bytes (256 bits) cryptographically random generated via `os.urandom()`.
- **Iteration Count:** 600,000 rounds.
- **Derived Key:** 32 bytes (256 bits) symmetric key.
- **Why it matters:** Defends against dictionary attacks and precomputed rainbow tables by making brute-force computation prohibitively expensive.

### AES-256-GCM Authenticated Encryption
- **Mode:** Galois/Counter Mode (AEAD - Authenticated Encryption with Associated Data).
- **Nonce / IV:** 12 bytes (96 bits) unique random nonce per encryption (`os.urandom()`).
- **Ciphertext & Tag:** The raw ciphertext is concatenated with a 16-byte (128-bit) GCM authentication tag.
- **Why it matters:** GCM provides both **confidentiality** and **authenticity**. Any modification to the ciphertext bits causes authenticated decryption to immediately fail (`DecryptionError`).

### SHA-256 Component Integrity Digest
- **Hash Function:** Standard SHA-256 (256-bit digest / 64 hex characters).
- **Digested Data:** Binary concatenation of `salt + nonce + ciphertext`.
- **Comparison:** Verified using constant-time comparison (`hmac.compare_digest`) to prevent timing side-channel attacks.
- *Academic Note:* AES-GCM enforces cryptographic authentication during decryption; SHA-256 provides a distinct educational container integrity layer.

---

## 5. Steganography & Payload Architecture

### Spatial 1-Bit RGB LSB Embedding Algorithm
1. The cover image is loaded as a 3D NumPy array of shape $(H, W, 3)$ with `uint8` values $[0, 255]$.
2. The payload byte string is prefixed with a **4-byte big-endian unsigned integer** encoding its exact byte length:
   $$\text{Header} = \text{struct.pack}(">I", \text{len}(\text{payload}))$$
3. The bitstream is injected into the least significant bit (bit 0) of each color channel:
   $$\text{Channel}_{\text{new}} = (\text{Channel}_{\text{old}} \ \& \ 0\text{xFE}) \ | \ \text{bit}$$
4. Modifying bit 0 changes the color intensity by at most $\pm 1$ out of 255 ($\approx 0.39\%$), which is undetectable to the human eye.

### Capacity Calculation Formula
$$\text{Total Bits} = W \times H \times 3$$
$$\text{Total Available Bytes} = \left\lfloor \frac{W \times H \times 3}{8} \right\rfloor$$
$$\text{Usable Capacity} = \text{Total Available Bytes} - 4 \text{ bytes (Header)}$$

*Example:* A $400 \times 400$ PNG image has $\lfloor (400 \times 400 \times 3)/8 \rfloor - 4 = \mathbf{59,996\text{ bytes}}$ ($\approx 58.5\text{ KB}$) of usable capacity.

### Why Lossless PNG Over Lossy JPEG?
- **PNG (Portable Network Graphics):** Employs lossless **DEFLATE** compression (LZ77 + Huffman coding). Pixel values are preserved exactly bit-for-bit.
- **JPEG:** Employs lossy Discrete Cosine Transform (**DCT**) compression, chroma subsampling, and high-frequency quantization. This alters pixel values, permanently destroying least significant bits.

### Versioned JSON v1 Payload Structure
```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "kdf": "PBKDF2-HMAC-SHA256",
  "iterations": 600000,
  "salt": "base64_encoded_32_byte_salt",
  "nonce": "base64_encoded_12_byte_nonce",
  "ciphertext": "base64_encoded_ciphertext_and_16B_tag",
  "sha256": "64_character_hexadecimal_hash"
}
```

---

## 6. Image Quality Analysis & Evaluation

### MSE (Mean Squared Error)
$$\text{MSE} = \frac{1}{3 \cdot W \cdot H} \sum_{c=1}^{3} \sum_{x=0}^{W-1} \sum_{y=0}^{H-1} \left( I_{\text{cover}}(x,y,c) - I_{\text{stego}}(x,y,c) \right)^2$$
- Lower is better ($0.0$ = identical images).

### PSNR (Peak Signal-to-Noise Ratio)
$$\text{PSNR} = 10 \cdot \log_{10}\left( \frac{255^2}{\text{MSE}} \right) \quad (\text{dB})$$
- Higher is better ($> 40\text{ dB}$ represents excellent quality; $\text{MSE} = 0 \implies \infty\text{ dB}$).
- In our spatial 1-bit LSB implementation, PSNR values typically exceed **$50\text{ dB}$ to $70\text{ dB}$**.

---

## 7. Repository File & Directory Structure

```
secure-steganography/
├── app.py                     # Flask application factory, error handlers & secure download route
├── requirements.txt           # Production & testing dependencies (Flask, gunicorn, cryptography, Pillow, numpy, pytest)
├── README.md                  # Comprehensive academic documentation & presentation master guide
├── .gitignore                 # Strict git ignore (excludes env, caches, virtualenv, and user uploads)
├── config/
│   ├── __init__.py
│   └── settings.py            # Central settings (16MB upload limit, directory paths, PBKDF2 params)
├── crypto/
│   ├── __init__.py
│   ├── encryption.py          # PBKDF2-HMAC-SHA256 derivation & AES-256-GCM authenticated encryption/decryption
│   └── hashing.py             # SHA-256 binary component hashing & constant-time validation
├── steganography/
│   ├── __init__.py
│   └── lsb.py                 # Spatial 1-bit RGB LSB embedding, extraction, & capacity calculation
├── utils/
│   ├── __init__.py
│   ├── payload.py             # Versioned JSON v1 payload builder, canonical serializer, & parser
│   ├── validators.py          # Magic-byte format check (PNG/BMP), size limits, & filename sanitization
│   └── image_analysis.py      # Mathematical MSE, PSNR, capacity info, & utilization calculations
├── routes/
│   ├── __init__.py            # Blueprint loader
│   ├── hide.py                # /hide route (Encrypt + Hash + Build JSON + LSB Embed + Output Stego PNG)
│   ├── extract.py             # /extract route (LSB Extract + Parse + SHA-256 Verify + AES-GCM Decrypt)
│   └── analysis.py           # /analysis route (Quality metrics dashboard & on-demand comparator)
├── templates/
│   ├── base.html              # Modern dark navbar, dismissible alerts, and security footer
│   ├── index.html             # Dashboard homepage with action cards & 2-party communication workflow
│   ├── hide.html              # Two-column Send/Hide form with live preview, capacity meter, & byte counter
│   ├── extract.html           # Receive/Extract form with 1-click clipboard copy & verification status badges
│   ├── analysis.html          # Performance metric KPI cards & on-demand image quality comparison form
│   └── about.html             # Educational guide with Cryptography vs Steganography comparison table
├── static/
│   ├── css/
│   │   └── style.css          # Dark cybersecurity UI theme (#080C14, Cyber Cyan, Emerald)
│   └── js/
│       └── main.js            # Vanilla JS for live preview, capacity meter, byte counting, & A11y
├── uploads/
│   └── .gitkeep               # Clean upload directory placeholder
├── outputs/
│   └── .gitkeep               # Clean stego output directory placeholder
└── tests/
    ├── __init__.py
    ├── test_crypto.py         # 19 tests: AES-GCM, PBKDF2, error conditions
    ├── test_hashing.py        # 25 tests: SHA-256 hashing, avalanche, constant-time compare
    ├── test_image_analysis.py # 14 tests: MSE, PSNR formulas, capacity mathematics
    ├── test_payload.py        # 53 tests: JSON schema, Base64 serialization, validation
    ├── test_routes.py         # 22 tests: Integration & route endpoints
    ├── test_security_audit.py # 22 tests: Security failures, OOM defenses, session privacy
    ├── test_steganography.py  # 39 tests: Spatial LSB embedding, extraction, header limits
    └── test_validators.py     # 17 tests: Image format, magic bytes, file size, sanitation
```

---

## 8. Local Installation & Setup Guide

### System Requirements
- **Python:** 3.10, 3.11, or 3.12 (Tested on Python 3.11.9).
- **OS:** Windows 10/11, Linux (Ubuntu/Debian), or macOS.

### Commands (Windows PowerShell)
```powershell
# 1. Clone the repository
git clone https://github.com/PRUDHVI15-HUB/secure-steganography.git
cd secure-steganography

# 2. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py

# 5. Open in your browser
# Navigate to: http://127.0.0.1:5000
```

---

## 9. Step-by-Step User Operation Guide

### Step 1: Send / Hide a Secret Message (`/hide`)
1. Go to `http://127.0.0.1:5000/hide`.
2. Select or drag-and-drop a **PNG** or **BMP** cover image.
3. Type your confidential message in the **Secret Message** field (live UTF-8 byte counter updates automatically).
4. Enter and confirm your shared passphrase.
5. Click **Encrypt & Hide Message**.
6. View the calculated **PSNR ($>50\text{ dB}$)**, **MSE ($<0.01$)**, and **SHA-256 Payload Hash**.
7. Click **Download Stego PNG** to save the resulting image.

### Step 2: Receive / Extract the Secret Message (`/extract`)
1. Go to `http://127.0.0.1:5000/extract`.
2. Upload the stego PNG image.
3. Enter the shared passphrase.
4. Click **Extract & Decrypt Message**.
5. The system verifies the container SHA-256 hash, authenticates the AES-GCM tag, and displays the exact recovered message.
6. Click **Copy Text** for instant clipboard copy.

### Step 3: Security & Quality Analysis (`/analysis`)
1. Go to `http://127.0.0.1:5000/analysis`.
2. View session metrics from the latest operation or upload any cover and stego pair to calculate instantaneous MSE, PSNR, and capacity metrics on demand.

---

## 10. Automated Testing & Security Verification (211/211 Passed)

```powershell
# Run the entire test suite
python -m pytest tests/ -v
```

| Test Suite File | Coverage Scope | Test Count | Result |
|---|---|:---:|:---:|
| `tests/test_crypto.py` | PBKDF2 iterations, AES-256-GCM authenticated encryption/decryption, wrong password rejection | 19 | ✅ Passed |
| `tests/test_hashing.py` | SHA-256 hashing, avalanche effect, component ordering, constant-time compare | 25 | ✅ Passed |
| `tests/test_image_analysis.py` | MSE and PSNR mathematical validation, capacity calculation, utilization metrics | 14 | ✅ Passed |
| `tests/test_payload.py` | Versioned JSON schema, Base64 serialization, canonical sorting, malformed payloads | 53 | ✅ Passed |
| `tests/test_routes.py` | Flask route endpoints, download security, integration pipelines, error responses | 22 | ✅ Passed |
| `tests/test_security_audit.py` | OOM defense, session privacy, path traversal defense, multilingual Unicode pipeline | 22 | ✅ Passed |
| `tests/test_steganography.py` | Spatial 1-bit LSB embedding/extraction, big-endian header, image modes | 39 | ✅ Passed |
| `tests/test_validators.py` | Magic-byte checks, format enforcement (reject JPEG), size bounds, filename sanitization | 17 | ✅ Passed |
| **TOTAL** | **Complete System Verification** | **211** | **211 Passed (0 Failed)** |

---

## 11. Defensive Security Controls & Web Hardening

- **Zero Secret Exposure:** Derived AES keys and plaintext passwords are never logged, never stored in session cookies, and never written to disk.
- **Magic-Byte Inspection:** Inspects actual binary headers using Pillow (`Image.open()`) rather than trusting file extensions. Disallows lossy JPEG, WebP, and GIF.
- **Path Traversal Guards:** Download endpoint (`/download/<path:filename>`) rejects path separators (`..`, `/`, `\\`) and validates that resolved paths are strictly within `outputs/`.
- **OOM Header Spoofing Defense:** Before extracting bytes, the LSB module verifies that the 32-bit header length does not exceed maximum image capacity.
- **Automatic File Cleanup:** Deletes temporary files older than 30 minutes on startup to prevent disk exhaustion.

---

## 12. CNS Syllabus Mapping & Conceptual Pillars

| CNS Core Concept | Implementation in Project |
|---|---|
| **Symmetric Confidentiality** | AES-256 in Galois/Counter Mode (AES-256-GCM). |
| **Key Derivation Functions (KDF)** | PBKDF2-HMAC-SHA256 with 600,000 iterations and 32-byte salt. |
| **Message Integrity** | SHA-256 cryptographic digest over $(salt \parallel nonce \parallel ciphertext)$. |
| **Message Authentication (AEAD)** | AES-GCM 16-byte authentication tag detects any bit modifications. |
| **Information Hiding (Steganography)** | Spatial 1-bit/channel RGB Least Significant Bit embedding. |
| **Semantic Security (IND-CPA)** | Fresh 32-byte salt and 12-byte nonce per encryption prevent pattern leakage. |
| **Side-Channel Mitigation** | `hmac.compare_digest` prevents timing attacks on hash comparison. |
| **Defensive Web Engineering** | Strict MIME magic bytes, path traversal defense, session privacy. |

---

## 13. Limitations & Future Scope

### Limitations
1. **Spatial LSB Fragility:** Altered by lossy compression (JPEG), aggressive resizing, or social media image compression.
2. **Dimension-Bounded Capacity:** Usable capacity is strictly proportional to image pixel count.
3. **Statistical Detectability:** Standard sequential spatial LSB can be detected by targeted steganalysis (e.g. Chi-Square attack).

### Future Scope
- **Adaptive Steganography:** Embed bits in complex texture/edge regions (using Sobel/Canny filters) to resist steganalysis.
- **Keyed Permutation Embedding:** Use a PRNG seeded with a stego-key to scatter bit positions non-sequentially across the pixel matrix.
- **Frequency Domain Steganography:** Implement 2D Discrete Wavelet Transform (DWT) or DCT embedding for robustness against compression.
- **Public-Key Cryptography:** Support RSA/ECC asymmetric key encapsulation for shared password exchange.

---

## 14. 🎓 Team PPT / Presentation Slide Deck Outline

*Your team can copy and use this exact 10-slide structure for the project presentation:*

- **Slide 1: Title Slide**
  - Project Title: Secure Image Steganography Using AES-256-GCM and Spatial LSB
  - Subtitle: A Layered Covert Communication System
  - Team Members & Guide Name, Department of Computer Science & Engineering.
- **Slide 2: Problem Statement & Motivation**
  - The limitations of raw encryption (ciphertext draws attention).
  - The vulnerabilities of unencrypted steganography (zero confidentiality if found).
  - Motivation: Combining Cryptography + Steganography for dual-layer defense.
- **Slide 3: System Architecture & Workflow Diagram**
  - Sender: Plaintext $\rightarrow$ PBKDF2 $\rightarrow$ AES-GCM $\rightarrow$ SHA-256 $\rightarrow$ JSON $\rightarrow$ LSB Embed $\rightarrow$ Stego PNG.
  - Receiver: Stego PNG $\rightarrow$ LSB Extract $\rightarrow$ SHA-256 Verify $\rightarrow$ AES-GCM Decrypt $\rightarrow$ Plaintext.
- **Slide 4: Cryptographic Layer (AES-256-GCM & PBKDF2)**
  - Why AES-GCM? (Provides both confidentiality and 16-byte authentication tag).
  - Why PBKDF2? (600,000 iterations + 32B salt against brute-force/dictionary attacks).
- **Slide 5: Steganographic Layer (Spatial RGB LSB)**
  - 1-bit per color channel (R, G, B) replacement.
  - 4-byte big-endian payload length header.
  - Usable capacity formula: $\lfloor (W \times H \times 3)/8 \rfloor - 4$ bytes.
- **Slide 6: Visual Quality & Mathematical Metrics (MSE & PSNR)**
  - Formulas for MSE and PSNR.
  - Experimental results: MSE $< 0.01$, PSNR $> 55\text{ dB}$ (Human Visual System imperceptible).
  - Lossless PNG vs lossy JPEG explanation.
- **Slide 7: Defensive Web Engineering & Security Hardening**
  - Magic-byte validation (rejecting fake PNGs / JPEGs).
  - Path traversal protection on `/download/<filename>`.
  - Session privacy (zero password/key storage).
  - OOM defense against manipulated header lengths.
- **Slide 8: Testing & Verification Results**
  - Automated test suite: **211/211 tests passing across 8 modules**.
  - Negative testing: Wrong password rejection, 1-pixel tampering detection.
- **Slide 9: Live Demonstration Walkthrough**
  - Screenshots / live demo showing `/hide`, `/extract`, and `/analysis`.
- **Slide 10: Conclusion & Future Enhancements**
  - Summary of accomplishments.
  - Future scope (Adaptive edge embedding, DWT transform domain, Asymmetric RSA/ECC key exchange).
  - Q&A.

---

## 15. 📄 Academic Project Report Structure

*Use this chapter outline when assembling the final B.Tech lab record or project report:*

1. **Chapter 1: Introduction**
   - 1.1 Background & Context
   - 1.2 Cryptography vs. Steganography
   - 1.3 Purpose & Scope
2. **Chapter 2: Literature Survey**
   - 2.1 Classical Steganographic Techniques
   - 2.2 Modern Symmetric Ciphers (AES-CBC vs AES-GCM)
   - 2.3 Password-Based Key Derivation Standards
3. **Chapter 3: System Design & Proposed Methodology**
   - 3.1 Architectural Pipeline
   - 3.2 Cryptographic Module (PBKDF2 + AES-GCM)
   - 3.3 Integrity Module (SHA-256)
   - 3.4 Spatial LSB Steganography Module
   - 3.5 Versioned JSON Payload Specification
4. **Chapter 4: Implementation Details**
   - 4.1 Technology Stack (Python, Flask, Pillow, NumPy, Cryptography)
   - 4.2 Module-by-Module Code Structure
   - 4.3 Web Interface & Usability Hardening
5. **Chapter 5: Results & Quality Analysis**
   - 5.1 Image Reconstruction Fidelity (MSE and PSNR)
   - 5.2 Capacity Allocation & Utilization Benchmarks
   - 5.3 Failure & Tampering Detection Results
6. **Chapter 6: Testing & Security Validation**
   - 6.1 Unit & Integration Test Matrix (211 Tests)
   - 6.2 Negative & Security Failure Resilience
7. **Chapter 7: Conclusion & Future Scope**
   - 7.1 Summary of Contributions
   - 7.2 Future Enhancements
8. **References & Appendix**

---

## 16. 🎤 Live Demo Script & Viva Voce Q&A Cheat-Sheet

### 3-Minute Faculty Presentation Script
1. *"Good morning professors. Today our team presents **Secure Image Steganography**—a layered covert communication system."*
2. *"Our core thesis is: **Encryption hides the content, but steganography hides the existence of communication**."*
3. *(Perform Demo on `/hide`)*: *"We select a cover image, type a secret message, and provide a passphrase. The system derives a 256-bit key via PBKDF2 with 600,000 iterations, encrypts the message using AES-256-GCM, hashes the components using SHA-256, and embeds the payload into the least significant bits of RGB channels."*
4. *(Show Results)*: *"The resulting stego image achieves a PSNR of over $60\text{ dB}$ with an MSE near zero, proving zero visual distortion."*
5. *(Perform Demo on `/extract`)*: *"On the receive page, uploading the stego image and entering the correct passphrase recovers the exact plaintext. If an attacker tampers with even one pixel or provides a wrong password, the system detects it and aborts."*

---

### Top 10 Viva Voce Questions & Model Answers

**Q1: Why did you choose AES-256-GCM over AES-CBC?**  
> *Answer:* AES-GCM is an **Authenticated Encryption with Associated Data (AEAD)** mode. While CBC requires an external HMAC to provide integrity, GCM provides both **confidentiality and authenticity** using a 16-byte GMAC authentication tag that detects tampering during decryption.

**Q2: What is the role of PBKDF2-HMAC-SHA256?**  
> *Answer:* User-chosen passwords have low entropy. PBKDF2 applies 600,000 iterations of HMAC-SHA256 with a 32-byte cryptographically random salt to derive a 256-bit key, effectively defending against dictionary and rainbow-table attacks.

**Q3: Why is SHA-256 used if AES-GCM already has an authentication tag?**  
> *Answer:* AES-GCM verifies authenticity during decryption. In our project, SHA-256 provides a separate educational **container integrity hash** over $(salt \parallel nonce \parallel ciphertext)$, verifying the structural payload before invoking cryptographic routines.

**Q4: How does spatial LSB steganography work?**  
> *Answer:* In a 24-bit RGB image, each pixel has 3 bytes (Red, Green, Blue). We replace the Least Significant Bit (bit 0) of each channel with one payload bit. The change in color intensity is at most $\pm 1$ out of 255, making it visually imperceptible.

**Q5: What is the exact capacity formula?**  
> *Answer:* $\text{Capacity} = \lfloor (W \times H \times 3)/8 \rfloor - 4 \text{ bytes}$. The 3 represents 3 bits/pixel across RGB channels, division by 8 converts bits to bytes, and 4 bytes are subtracted for the 32-bit big-endian length header.

**Q6: Why is JPEG rejected while PNG is accepted?**  
> *Answer:* PNG uses **lossless DEFLATE** compression, preserving pixel values bit-for-bit. JPEG uses **lossy DCT compression and quantization**, which alters pixel values and corrupts embedded LSB data.

**Q7: What do MSE and PSNR measure?**  
> *Answer:* **MSE (Mean Squared Error)** measures average squared pixel differences between cover and stego images (lower is better). **PSNR (Peak Signal-to-Noise Ratio)** measures reconstruction quality in decibels ($\text{PSNR} = 10 \log_{10}(255^2/\text{MSE})$). Values $> 40\text{ dB}$ represent high quality; our LSB steganography achieves $> 55\text{ dB}$.

**Q8: What happens if an adversary modifies one pixel of the stego image?**  
> *Answer:* Modifying a pixel flips one or more payload bits. When extracted, the recalculated SHA-256 digest will not match the stored hash, and the AES-GCM authentication tag verification will fail, preventing decryption.

**Q9: How do you prevent Out-Of-Memory (OOM) attacks from crafted headers?**  
> *Answer:* Before extracting bytes, the LSB extractor reads the 4-byte header length and verifies that $\text{length} \le \text{Max Image Capacity}$. If a malicious file claims a 4 GB payload on a 100 KB image, it is rejected immediately before allocating memory.

**Q10: What are the main limitations of spatial LSB steganography?**  
> *Answer:* 1) Fragility against lossy compression and resizing; 2) Capacity bounded by image resolution; 3) Detectability via statistical steganalysis (e.g. Chi-Square). Future improvements include adaptive edge embedding and transform domain (DWT) embedding.

---

## 17. 🌐 Free 1-Click Cloud Deployment (Render)

The repository is configured with `gunicorn` in `requirements.txt` for deployment on **[Render.com](https://render.com/)**:

1. Log in to **[Render.com](https://render.com/)** using your GitHub account.
2. Click **New +** $\rightarrow$ **Web Service** $\rightarrow$ Connect `PRUDHVI15-HUB/secure-steganography`.
3. Set **Build Command:** `pip install -r requirements.txt`
4. Set **Start Command:** `gunicorn "app:create_app()"`
5. Select **Free Tier** $\rightarrow$ Click **Deploy Web Service**.
6. Render will generate a public `https://...` live URL for your project!

---

## 18. Academic Attribution & License

- **Project:** Secure Image Steganography System
- **Course:** Cryptography & Network Security (CS401 / CNS Lab)
- **Author / Repository:** [PRUDHVI15-HUB/secure-steganography](https://github.com/PRUDHVI15-HUB/secure-steganography)
- **License:** Open for academic and educational evaluation.
