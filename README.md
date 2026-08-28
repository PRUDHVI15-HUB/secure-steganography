# Secure Image Steganography: AES-256-GCM + SHA-256 + Spatial LSB Steganography

### *A Layered Covert Communication System Combining Authenticated Encryption, Cryptographic Integrity Verification, and Spatial-Domain Image Steganography*

---

## 📑 Master Table of Contents

1. [Academic Information & Project Metadata](#1-academic-information--project-metadata)
2. [Academic Abstract](#2-academic-abstract)
3. [Introduction & Core Philosophy](#3-introduction--core-philosophy)
4. [Problem Statement](#4-problem-statement)
5. [Project Objectives](#5-project-objectives)
6. [System Overview & Beginner Workflow](#6-system-overview--beginner-workflow)
7. [User Interface & Application Routes](#7-user-interface--application-routes)
8. [System Architecture & Block Diagrams](#8-system-architecture--block-diagrams)
9. [Complete End-to-End Data Flow](#9-complete-end-to-end-data-flow)
10. [Password-Based Key Derivation (PBKDF2-HMAC-SHA256)](#10-password-based-key-derivation-pbkdf2-hmac-sha256)
11. [Authenticated Symmetric Encryption (AES-256-GCM)](#11-authenticated-symmetric-encryption-aes-256-gcm)
12. [Cryptographic Integrity Digest (SHA-256)](#12-cryptographic-integrity-digest-sha-256)
13. [Versioned Payload Architecture (JSON v1)](#13-versioned-payload-architecture-json-v1)
14. [Spatial Least Significant Bit (LSB) Steganography](#14-spatial-least-significant-bit-lsb-steganography)
15. [Steganographic Capacity Mathematics](#15-steganographic-capacity-mathematics)
16. [Image Format & Magic-Byte Validation](#16-image-format--magic-byte-validation)
17. [Image Quality Analysis (MSE & PSNR)](#17-image-quality-analysis-mse--psnr)
18. [Defensive Security Controls & Web Hardening](#18-defensive-security-controls--web-hardening)
19. [Threat Model & Failure Handling Scenarios](#19-threat-model--failure-handling-scenarios)
20. [Security Limitations & Academic Boundaries](#20-security-limitations--academic-boundaries)
21. [Automated Verification & Test Suite Matrix (211/211 Passed)](#21-automated-verification--test-suite-matrix-211211-passed)
22. [Security Audit & Resilience Testing](#22-security-audit--resilience-testing)
23. [Step-by-Step Faculty Demonstration Script](#23-step-by-step-faculty-demonstration-script)
24. [Beginner & Faculty User Guide (FAQ)](#24-beginner--faculty-user-guide-faq)
25. [Verified Technology Stack](#25-verified-technology-stack)
26. [Repository File & Directory Structure](#26-repository-file--directory-structure)
27. [Local Installation & Execution Guide](#27-local-installation--execution-guide)
28. [Academic CNS Syllabus & Curriculum Mapping](#28-academic-cns-syllabus--curriculum-mapping)
29. [Viva Voce Examination Preparation (22 Questions & Model Answers)](#29-viva-voce-examination-preparation-22-questions--model-answers)
30. [Current Implementation vs. Future Enhancements](#30-current-implementation-vs-future-enhancements)
31. [Screenshot & Visual Asset Documentation](#31-screenshot--visual-asset-documentation)
32. [PowerPoint Presentation (PPT) Generation Guide (15 Slides)](#32-powerpoint-presentation-ppt-generation-guide-15-slides)
33. [Academic Project Report Chapter Outline (21 Sections)](#33-academic-project-report-chapter-outline-21-sections)
34. [Team Handoff & Collaboration Notes](#34-team-handoff--collaboration-notes)
35. [Final Project Verification Status](#35-final-project-verification-status)

---

## 1. Academic Information & Project Metadata

```
================================================================================
                    ACADEMIC PROJECT DETAILS & METADATA
================================================================================
Institution        : [ENTER COLLEGE / UNIVERSITY NAME HERE]
Department         : Department of Computer Science and Engineering
Course / Subject   : Cryptography and Network Security (CNS)
Laboratory         : Cryptography & Network Security Laboratory (CS401 / CNS Lab)
Academic Year      : 2025 – 2026 (Semester VII / VIII)
Project Title      : Secure Image Steganography: AES-256-GCM + SHA-256 + Spatial LSB

Team Lead          : [ENTER TEAM LEAD NAME]    (Roll No: [ENTER ROLL NO])
Team Member 2      : [ENTER MEMBER 2 NAME]     (Roll No: [ENTER ROLL NO])
Team Member 3      : [ENTER MEMBER 3 NAME]     (Roll No: [ENTER ROLL NO])
Team Member 4      : [ENTER MEMBER 4 NAME]     (Roll No: [ENTER ROLL NO])

Faculty Guide      : [ENTER FACULTY / PROFESSOR NAME]
Lab Instructor     : [ENTER LAB INSTRUCTOR NAME]
Date of Submission : [ENTER SUBMISSION DATE]
Repository Link    : https://github.com/PRUDHVI15-HUB/secure-steganography
================================================================================
```

---

## 2. Academic Abstract

In contemporary network security, transmitting raw ciphertext across monitored communication channels exposes the existence of confidential exchanges, inviting interception, traffic analysis, and adversarial interference. Conversely, conventional image steganography conceals the presence of data within innocuous multimedia carriers, but offers zero cryptographic confidentiality if the underlying embedding algorithm is identified.

This laboratory project presents a unified, defense-in-depth covert communication system integrating authenticated symmetric cryptography with spatial-domain image steganography. Confidential plaintext messages are encrypted using **AES-256-GCM** (Galois/Counter Mode) utilizing 256-bit symmetric keys derived from human-memorable passphrases via **PBKDF2-HMAC-SHA256** configured with 600,000 iterations and a 32-byte cryptographically random salt. An independent **SHA-256** digest computed over the binary concatenation of cryptographic parameters $(salt \parallel nonce \parallel ciphertext)$ establishes structural container integrity prior to decryption.

The resulting canonical, versioned JSON payload (v1) is serialized to Base64 and embedded into the least significant bit (bit 0) of lossless 24-bit RGB color channels preceded by a 4-byte big-endian length header. Reconstruction fidelity is mathematically verified via Mean Squared Error (**MSE**) and Peak Signal-to-Noise Ratio (**PSNR**), consistently demonstrating imperceptible visual degradation ($PSNR > 55\text{ dB}$, $MSE < 0.01$). The software architecture is implemented in Python and Flask, protected against common web vulnerabilities, and verified by a comprehensive automated test suite of **211 test cases across 8 test suites with 100% pass rate**.

---

## 3. Introduction & Core Philosophy

### Cryptography vs. Steganography
- **Cryptography** (Secret Writing): Scrambles plaintext into an unintelligible ciphertext using mathematical keys. It protects data **confidentiality**, but the visible presence of ciphertext explicitly alerts an observer that a secret exists.
- **Steganography** (Covered Writing): Hides the secret payload inside an innocent cover medium (such as a digital image) such that an unauthorized observer cannot perceive that any communication is taking place.

### The Synergistic Dual-Layer Defense
Neither technique alone is sufficient in a hostile network environment:
1. *Cryptography alone* draws suspicion: An encrypted email or binary file attached across corporate or monitored firewalls triggers Data Loss Prevention (DLP) alerts.
2. *Steganography alone* lacks security: If a passive attacker extracts the least significant bits, the underlying message is immediately readable in plaintext.

> **Fundamental Principle:**  
> *"Encryption conceals the CONTENT of the message, while steganography conceals the EXISTENCE of the communication."*

By combining **PBKDF2-HMAC-SHA256 key stretching**, **AES-256-GCM authenticated encryption**, **SHA-256 integrity verification**, and **Spatial 1-Bit RGB LSB Steganography**, this system ensures that even if the carrier image is intercepted, it appears completely innocent; and even if an adversary suspects and extracts the raw embedded bits, they face military-grade authenticated encryption.

---

## 4. Problem Statement

Modern communication over untrusted networks faces four critical vulnerabilities:
1. **Plaintext Exposure:** Unprotected text sent across network links is subject to eavesdropping.
2. **Traffic & Ciphertext Visibility:** Transmitting raw encrypted blobs alerts automated deep-packet inspection (DPI) firewalls, making the sender a target of surveillance.
3. **Ciphertext Tampering:** Standard unauthenticated block cipher modes (such as AES-CBC or AES-CTR without MAC) are vulnerable to bit-flipping attacks where adversaries alter ciphertext in transit without detection.
4. **Weak Key Derivation:** Direct password-to-key mapping enables dictionary and rainbow-table attacks.
5. **Lossy Compression Distortion:** Embedding data into lossy image formats (like JPEG) leads to catastrophic bit corruption due to discrete cosine transform (DCT) quantization.

### How This Project Solves These Issues:
- **AES-256-GCM** guarantees confidentiality and provides a 16-byte authentication tag to detect any ciphertext tampering.
- **PBKDF2-HMAC-SHA256 (600,000 rounds + 32-byte salt)** makes password brute-forcing computationally prohibitive.
- **SHA-256 Integrity Hashing** verifies container consistency prior to invoking cryptographic routines.
- **Spatial 1-Bit RGB LSB Embedding** conceals data invisibly inside lossless PNG/BMP pixel matrices.
- **Strict Magic-Byte Validation** disallows lossy image formats (JPEG, WebP) to prevent payload destruction.

---

## 5. Project Objectives

1. **Implement Robust Password-Based Key Derivation:** Utilize PBKDF2-HMAC-SHA256 with 600,000 iterations and fresh 32-byte cryptographic salts to generate 256-bit AES keys.
2. **Deliver Authenticated Symmetric Encryption:** Encrypt plaintext using AES-256-GCM with a unique 12-byte nonce per operation and generate a 16-byte GMAC authentication tag.
3. **Provide Independent Container Integrity Verification:** Compute and verify a SHA-256 digest over cryptographic parameters $(salt \parallel nonce \parallel ciphertext)$.
4. **Construct a Canonical Versioned Payload Structure:** Design a versioned JSON schema (v1) with Base64 encoding for safe transport across binary and text boundaries.
5. **Execute Spatial-Domain LSB Steganography:** Embed bitstreams into the least significant bit (bit 0) of 24-bit RGB image channels preceded by a 4-byte big-endian length header.
6. **Enforce Strict Input & Image Validation:** Validate file sizes (16 MB limit), verify MIME magic bytes (PNG/BMP), sanitize filenames against path traversal, and enforce capacity boundaries.
7. **Evaluate Image Degradation Mathematically:** Provide real-time Mean Squared Error (MSE) and Peak Signal-to-Noise Ratio (PSNR) analysis directly from uncompressed pixel buffers.
8. **Develop a Hardened Web Application:** Build a defensive Flask application with dark cybersecurity styling, client-side capacity meters, live UTF-8 byte counting, and zero session-based credential leakage.
9. **Ensure 100% Test Coverage:** Build comprehensive automated unit, integration, and security-failure test suites (211 verified passing tests).

---

## 6. System Overview & Beginner Workflow

### Two-Party Covert Communication Model

```
SENDER                                                     RECEIVER
  │                                                           │
  ├─ 1. Select Cover PNG/BMP                                  │
  ├─ 2. Type Secret Message                                   │
  ├─ 3. Set Secret Passphrase                                 │
  ├─ 4. Generate Stego PNG                                    │
  │                                                           │
  ├─────── [Public / Unmonitored Channel] ───────────────────►│ (Stego PNG)
  ├─────── [Private / Out-of-Band Channel] ──────────────────►│ (Shared Passphrase)
  │                                                           │
  │                                                           ├─ 5. Upload Stego PNG
  │                                                           ├─ 6. Enter Passphrase
  │                                                           ├─ 7. Verify Integrity
  │                                                           ├─ 8. Authenticate & Decrypt
  │                                                           └─ 9. Read Secret Plaintext
```

### Important Real-World Note
- **The passphrase is NEVER stored in the image** and is **NEVER automatically transmitted**.
- The sender and receiver must agree on the passphrase beforehand or share it via a separate secure out-of-band channel (e.g., in person or via encrypted voice).
- If the receiver enters an incorrect password or if a single pixel in the stego image is altered, the system safely aborts and displays a clear security error.

---

## 7. User Interface & Application Routes

The web application exposes 5 primary routes and a secure file download endpoint:

| Route | HTTP Method | Route Name | Purpose & Workflow |
|---|:---:|---|---|
| `/` | `GET` | **Home Dashboard** | Introduces the system, displays the sender/receiver workflow, and provides quick navigation cards. |
| `/hide` | `GET`, `POST` | **Send / Hide Message** | Uploads a cover image, validates capacity, derives key, executes AES-GCM encryption, hashes container, and embeds payload into a downloadable Stego PNG. |
| `/extract` | `GET`, `POST` | **Receive / Extract Message** | Uploads a stego image, extracts LSB bitstream, verifies SHA-256 integrity, validates AES-GCM tag, derives key, and reveals decrypted plaintext. |
| `/analysis` | `GET`, `POST` | **Security Analysis** | Displays MSE, PSNR, payload utilization, and capacity metrics from recent operations or on-demand cover/stego image comparisons. |
| `/about` | `GET` | **Educational Theory** | Academic reference guide explaining AES-GCM vs AES-CBC, SHA-256 vs GCM tags, and Cryptography vs Steganography. |
| `/download/<filename>` | `GET` | **Secure File Download** | Securely streams generated stego images from the `outputs/` directory with strict path-traversal prevention. |

---

## 8. System Architecture & Block Diagrams

### Sender Architecture (Embedding Pipeline)
```
[ User Input: Plaintext Message + Passphrase ]
                      │
                      ▼
            [ Input Validation ] ── (Length, Format, Empty Checks)
                      │
                      ▼
         [ PBKDF2-HMAC-SHA256 KDF ] ◄── (os.urandom(32) Salt + 600,000 Iterations)
                      │
                      ▼ 256-bit Key
            [ AES-256-GCM Encrypt ] ◄── (os.urandom(12) Nonce)
                      │
                      ▼ Ciphertext || 16-byte Auth Tag
           [ SHA-256 Hash Function ] ──► Computes Digest over (Salt || Nonce || Ciphertext)
                      │
                      ▼
          [ JSON Payload Builder (v1) ] ── (Base64 Encode Salt, Nonce, Ciphertext)
                      │
                      ▼ Canonical JSON String (UTF-8 Bytes)
        [ Big-Endian Length Prefix (4B) ] ── (struct.pack(">I", len(payload)))
                      │
                      ▼
         [ Spatial RGB LSB Embedder ] ◄── Cover PNG Pixel Array (H, W, 3)
                      │
                      ▼
             [ Stego PNG Output ] ──► Image Quality Analysis (MSE / PSNR)
```

### Receiver Architecture (Extraction Pipeline)
```
[ User Input: Stego PNG Image + Shared Passphrase ]
                      │
                      ▼
          [ Image Format Validation ] ── (Magic Bytes, PNG/BMP Check)
                      │
                      ▼
        [ Spatial RGB LSB Extractor ]
                      │
                      ├─► 1. Extract first 32 bits ──► Parse 4-Byte Payload Length
                      ├─► 2. Validate Length against Image Capacity (OOM Defense)
                      └─► 3. Extract (Length * 8) bits ──► Reconstruct Payload Bytes
                      │
                      ▼
           [ JSON Payload Parser ] ── (Validate Schema, Decode Base64)
                      │
                      ▼ Extracted Salt, Nonce, Ciphertext, SHA-256 Digest
         [ SHA-256 Integrity Check ] ── (hmac.compare_digest(stored, recomputed))
                      │  [If Mismatch ──► IntegrityError]
                      ▼ [If Match]
         [ PBKDF2-HMAC-SHA256 KDF ] ◄── (Passphrase + Extracted Salt)
                      │
                      ▼ Re-derived 256-bit Key
            [ AES-256-GCM Decrypt ] ◄── (Extracted Nonce + Ciphertext + Tag)
                      │  [If Invalid Tag / Wrong Pass ──► DecryptionError]
                      ▼ [If Authenticated]
           [ Recovered Plaintext ] ──► Rendered on Secure Web Interface
```

---

## 9. Complete End-to-End Data Flow

### Step-by-Step Mathematical & Binary Transformations

#### Sender Side:
1. **Plaintext Input:** $M = \text{"Hello CNS Lab"}$ (UTF-8 encoded bytes).
2. **Salt Generation:** $S = \text{os.urandom}(32)$ (256-bit random salt).
3. **Key Derivation:** $K = \text{PBKDF2-HMAC-SHA256}(P, S, c=600000, dklen=32)$.
4. **Nonce Generation:** $N = \text{os.urandom}(12)$ (96-bit unique nonce).
5. **Encryption & Authentication:** $(C \parallel T) = \text{AES-GCM-Encrypt}(K, N, M)$, where $T$ is the 16-byte authentication tag.
6. **Integrity Hashing:** $H = \text{SHA-256}(S \parallel N \parallel (C \parallel T))$ (64-character hex string).
7. **Payload Assembly:** A Python dictionary with keys `version=1`, `algorithm="AES-256-GCM"`, `kdf="PBKDF2-HMAC-SHA256"`, `iterations=600000`, `salt=\text{b64}(S)`, `nonce=\text{b64}(N)`, `ciphertext=\text{b64}(C \parallel T)`, `sha256=H`.
8. **Canonical Serialization:** $B = \text{json.dumps}(\text{payload}, sort\_keys=True, separators=(',', ':')).encode('utf-8')$.
9. **Header Framing:** $D = \text{struct.pack}(">I", \text{len}(B)) \parallel B$.
10. **LSB Injection:** Bits of $D$ are sequentially placed into the least significant bit of color channels across coordinates $(y, x, c)$.

#### Receiver Side:
1. **Header Parsing:** Extract first 32 bits $\rightarrow L = \text{struct.unpack}(">I", \text{header\_bytes})[0]$.
2. **Capacity Boundary Check:** Assert $L \le \text{Max Image Capacity}$.
3. **Bit Reconstruction:** Read $L \times 8$ channel bits to assemble byte buffer $B$.
4. **JSON Parsing & Base64 Decoding:** Reconstruct $S, N, (C \parallel T),$ and $H$.
5. **Digest Verification:** Assert $\text{hmac.compare\_digest}(H, \text{SHA-256}(S \parallel N \parallel (C \parallel T))) == \text{True}$.
6. **Key Regeneration:** $K' = \text{PBKDF2-HMAC-SHA256}(P_{\text{entered}}, S, c=600000, dklen=32)$.
7. **Authenticated Decryption:** $M = \text{AES-GCM-Decrypt}(K', N, C \parallel T)$.
8. **Plaintext Recovery:** Decode $M$ as UTF-8 string.

---

## 10. Password-Based Key Derivation (PBKDF2-HMAC-SHA256)

Human-chosen passwords exhibit low entropy and are vulnerable to dictionary search. PBKDF2 (Password-Based Key Derivation Function 2) normalizes passwords into a uniform 256-bit key space.

```
Password: "my_secure_password"
       │
       ├──────────────────────────────────────────────┐
       ▼                                              ▼
[ 32-Byte Random Salt ]                     [ 600,000 Iterations ]
(Cryptographically random)                  (HMAC-SHA256 loop)
       │                                              │
       └──────────────────────┬───────────────────────┘
                              ▼
               [ 256-Bit Symmetric AES Key ]
```

### Verified Implementation Parameters (`crypto/encryption.py`)
- **Pseudorandom Function (PRF):** HMAC-SHA256 (`hashes.SHA256()`).
- **Iteration Count:** `600_000` rounds (aligned with current OWASP/NIST standards).
- **Salt Length:** `32` bytes (256 bits) generated via `os.urandom(32)`.
- **Derived Key Length:** `32` bytes (256 bits).
- **Storage Policy:** The salt is stored publicly in the payload container; it is not secret. The password is never stored or logged anywhere.

---

## 11. Authenticated Symmetric Encryption (AES-256-GCM)

AES (Advanced Encryption Standard) in Galois/Counter Mode is an **AEAD** (Authenticated Encryption with Associated Data) scheme that provides confidentiality, integrity, and authenticity in a single cryptographic pass.

### Verified Parameters (`crypto/encryption.py`)
- **Cipher:** AES-256 (256-bit key).
- **Mode:** Galois/Counter Mode (GCM).
- **Nonce (IV):** 12 bytes (96 bits) cryptographically random per operation (`os.urandom(12)`).
- **Authentication Tag:** 16 bytes (128 bits) computed over ciphertext via GHASH.
- **Combined Ciphertext:** Python `cryptography` outputs `ciphertext || tag` (tag is the last 16 bytes).

### Comparison: AES-CBC vs. AES-GCM

| Feature / Metric | AES-CBC (Cipher Block Chaining) | AES-256-GCM (Galois/Counter Mode) |
|---|---|---|
| **Confidentiality** | Yes | Yes |
| **Authentication / Integrity** | No (Requires separate HMAC) | **Yes (Built-in 16-byte GHASH tag)** |
| **Tamper Detection** | Vulnerable to padding oracle attacks | **Immediate rejection (`InvalidTag`)** |
| **Padding Required** | Yes (PKCS#7 to 16-byte block boundary) | **No (Stream cipher mode)** |
| **Nonce Requirements** | 16-byte random IV | **12-byte unique random nonce** |
| **Suitability for CNS Project** | Legacy / Incomplete | **Optimal / Industry Standard** |

---

## 12. Cryptographic Integrity Digest (SHA-256)

### Purpose & Distinction
- **AES-GCM Authentication:** Verified inside the decryption engine using the 16-byte GMAC tag and derived key.
- **SHA-256 Container Digest:** An independent educational container integrity layer. It computes a fixed 256-bit (32-byte / 64-character hex) digest over:
  $$\text{Digest} = \text{SHA-256}(salt \parallel nonce \parallel ciphertext)$$
- **Constant-Time Verification:** Verified using Python's `hmac.compare_digest()` to prevent timing side-channel attacks.

---

## 13. Versioned Payload Architecture (JSON v1)

The system packages all cryptographic parameters into a canonical, versioned JSON payload (`utils/payload.py`).

### Schema Definition (Version 1)
```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "kdf": "PBKDF2-HMAC-SHA256",
  "iterations": 600000,
  "salt": "dGVzdF9zYWx0XzMyX2J5dGVzX2xvbmdfZXhhbXBsZQ==",
  "nonce": "ZXhhbXBsZV9ub25jZQ==",
  "ciphertext": "ZXhhbXBsZV9lbmNyeXB0ZWRfY2lwaGVydGV4dF9hbmRfdGFn==",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### Key Properties:
- **Base64 Encoding:** Binary buffers (`salt`, `nonce`, `ciphertext`) are encoded as Base64 strings to ensure lossless JSON serialization.
- **Deterministic Canonicalization:** Serialized using `json.dumps(obj, sort_keys=True, separators=(',', ':'))` for deterministic byte ordering.
- **Schema Validation:** Strict type and length checks prevent malformed payloads or unexpected keys from executing.

---

## 14. Spatial Least Significant Bit (LSB) Steganography

Spatial LSB steganography modifies the least significant bit (bit 0) of each color byte in an uncompressed 24-bit RGB image.

### Mathematical Bit Manipulation
For an 8-bit color channel value $C \in [0, 255]$ and payload bit $b \in \{0, 1\}$:
$$C_{\text{stego}} = (C \ \& \ 0\text{xFE}) \ | \ b$$

### Example Bitwise Operation:
```
Original Color Byte (Green) : 1 0 1 1 0 1 1 0   (Value: 182)
Mask with 0xFE (11111110)   : 1 0 1 1 0 1 1 0   (LSB cleared)
Payload Bit to embed        :               1
Resulting Stego Byte        : 1 0 1 1 0 1 1 1   (Value: 183)
```
- **Magnitude of Change:** Maximum $\pm 1$ out of 255 ($\approx 0.39\%$).
- **Visual Impact:** Completely undetectable to the Human Visual System (HVS).

---

## 15. Steganographic Capacity Mathematics

### Capacity Formula
Each RGB pixel has 3 color channels (Red, Green, Blue), contributing 3 bits of storage:
$$\text{Total Available Bits} = W \times H \times 3$$
$$\text{Total Available Bytes} = \left\lfloor \frac{W \times H \times 3}{8} \right\rfloor$$
$$\text{Usable Payload Capacity} = \left\lfloor \frac{W \times H \times 3}{8} \right\rfloor - 4 \text{ bytes (Header)}$$

### Numerical Capacity Table

| Image Dimensions | Total Pixels | Total Bits | Total Raw Bytes | Usable Capacity (Bytes) | Usable Capacity (KB) |
|:---:|:---:|:---:|:---:|:---:|:---:|
| $100 \times 100$ | 10,000 | 30,000 | 3,750 | **3,746 B** | 3.65 KB |
| $400 \times 400$ | 160,000 | 480,000 | 60,000 | **59,996 B** | 58.58 KB |
| $800 \times 600$ | 480,000 | 1,440,000 | 180,000 | **179,996 B** | 175.77 KB |
| $1920 \times 1080$ | 2,073,600 | 6,220,800 | 777,600 | **777,596 B** | 759.37 KB |

---

## 16. Image Format & Magic-Byte Validation

### Why Lossless PNG/BMP vs Lossy JPEG?
- **PNG (Portable Network Graphics):** Uses **DEFLATE** (lossless compression). Pixel values stored are reconstructed identically bit-for-bit.
- **BMP (Bitmap):** Uncompressed raster graphics. Retains exact pixel arrays.
- **JPEG (Joint Photographic Experts Group):** Uses **lossy DCT compression**, chrominance subsampling, and high-frequency quantization. This alters pixel values, permanently destroying LSB modifications.

### Validation Engine (`utils/validators.py`)
- **Magic-Byte Inspection:** Uses Pillow (`Image.open()`) to inspect the actual binary header rather than trusting user-supplied file extensions.
- **Strict Format Allowlist:** Only `PNG` and `BMP` are accepted. Files with extensions like `.jpg`, `.jpeg`, `.webp`, or `.gif` are rejected with descriptive user alerts.

---

## 17. Image Quality Analysis (MSE & PSNR)

### Mean Squared Error (MSE)
Calculates the average squared difference across all RGB channels between original cover image $I$ and stego image $K$:
$$\text{MSE} = \frac{1}{3 \cdot W \cdot H} \sum_{c=1}^{3} \sum_{x=0}^{W-1} \sum_{y=0}^{H-1} \left[ I(x, y, c) - K(x, y, c) \right]^2$$

### Peak Signal-to-Noise Ratio (PSNR)
Measures reconstruction fidelity in decibels (dB) relative to maximum pixel power ($255^2$):
$$\text{PSNR} = 10 \cdot \log_{10}\left( \frac{255^2}{\text{MSE}} \right) \quad (\text{dB})$$
- When $\text{MSE} = 0$ (identical images), $\text{PSNR} = \infty\text{ dB}$ (`float('inf')`).
- Higher PSNR indicates superior quality. PSNR values above $40\text{ dB}$ are considered imperceptible to human vision; our system consistently achieves **$55\text{ dB}$ to $75\text{ dB}$**.

---

## 18. Defensive Security Controls & Web Hardening

| Security Category | Mechanism Implemented | Source Module |
|---|---|---|
| **Key Derivation** | PBKDF2-HMAC-SHA256 (600,000 iterations, 32B salt) | `crypto/encryption.py` |
| **Cipher Authenticity** | AES-256-GCM with 16-byte authentication tag | `crypto/encryption.py` |
| **Integrity Verification** | Constant-time SHA-256 comparison (`hmac.compare_digest`) | `crypto/hashing.py` |
| **MIME Validation** | Binary header magic-byte verification (Pillow) | `utils/validators.py` |
| **Path Traversal Defense** | `secure_filename` + path resolution confinement | `app.py`, `utils/validators.py` |
| **Memory Exhaustion (OOM)** | Header length validated against max image capacity | `steganography/lsb.py` |
| **Session Privacy** | Zero password or plaintext caching in cookies/sessions | `routes/hide.py`, `routes/extract.py` |
| **File Cleanup** | Automatic purging of temp files older than 30 minutes | `app.py` |
| **Upload Size Guard** | 16 MB maximum file upload boundary (`MAX_CONTENT_LENGTH`) | `config/settings.py` |

---

## 19. Threat Model & Failure Handling Scenarios

| Threat / Failure Scenario | Trigger Condition | System Detection & Handling |
|---|---|---|
| **1. Authorized Decryption** | Valid Stego PNG + Correct Password | SHA-256 digest verified $\rightarrow$ AES-GCM authenticated $\rightarrow$ Plaintext displayed. |
| **2. Unauthorized Access** | Valid Stego PNG + Wrong Password | AES-GCM tag mismatch $\rightarrow$ `DecryptionError` raised $\rightarrow$ "Authentication failed. Incorrect password." |
| **3. Pixel Tampering** | 1 or more stego pixels altered | SHA-256 digest mismatch $\rightarrow$ `IntegrityError` raised $\rightarrow$ "Payload integrity verification failed." |
| **4. Corrupted Image** | Truncated / malformed PNG file | Pillow raises `UnidentifiedImageError` $\rightarrow$ "The uploaded file is corrupted or not a valid image." |
| **5. Extension Spoofing** | JPEG renamed to `.png` | Magic-byte inspector detects JPEG format $\rightarrow$ "JPEG images use lossy compression and are not supported." |
| **6. Unsupported Format** | Uploading `.webp`, `.gif`, `.exe` | Extension/format validator rejects file $\rightarrow$ "Unsupported file format. Please upload PNG or BMP." |
| **7. Capacity Overflow** | Payload larger than image capacity | Capacity checker calculates bounds $\rightarrow$ `CapacityError` raised $\rightarrow$ "Payload exceeds image capacity." |
| **8. Header Length Spoofing** | Header claims 4 GB on 100 KB image | LSB extractor asserts $L \le \text{Max Capacity}$ $\rightarrow$ Rejects before memory allocation (OOM defense). |
| **9. Path Traversal** | Requesting `/download/../../etc/passwd` | Sanitizer strips path separators $\rightarrow$ Aborts with `404 Not Found`. |
| **10. Multilingual Unicode** | Message with Emoji / Asian scripts | Handled losslessly via Python UTF-8 encoding. |

---

## 20. Security Limitations & Academic Boundaries

1. **Spatial LSB Fragility:** Spatial LSB embedding is fragile against lossy recompression (JPEG), geometric transformations (scaling, rotation), and social media image re-encoding.
2. **Dimension-Dependent Capacity:** Storage capacity is strictly constrained by image resolution.
3. **Statistical Steganalysis Vulnerability:** Pure sequential spatial LSB replacement can be detected by targeted statistical steganalysis (such as Chi-Square or Sample Pairs analysis).
4. **Educational Scope:** Designed as an educational CNS laboratory demonstration platform, not as a covert-channel malware tool.

---

## 21. Automated Verification & Test Suite Matrix (211/211 Passed)

```powershell
# Command to execute full test suite
python -m pytest tests/ -v
```

| Test Suite Module | Target Component | Test Count | Status |
|---|---|:---:|:---:|
| [`tests/test_crypto.py`](file:///c:/Users/USER/Desktop/CNS%20LAB%20PROJECT/secure-steganography/tests/test_crypto.py) | PBKDF2 iterations, AES-256-GCM encryption/decryption, wrong password handling | 19 | ✅ Passed |
| [`tests/test_hashing.py`](file:///c:/Users/USER/Desktop/CNS%20LAB%20PROJECT/secure-steganography/tests/test_hashing.py) | SHA-256 hashing, avalanche effect, component ordering, constant-time compare | 25 | ✅ Passed |
| [`tests/test_image_analysis.py`](file:///c:/Users/USER/Desktop/CNS%20LAB%20PROJECT/secure-steganography/tests/test_image_analysis.py) | MSE and PSNR mathematical validation, capacity calculation, utilization metrics | 14 | ✅ Passed |
| [`tests/test_payload.py`](file:///c:/Users/USER/Desktop/CNS%20LAB%20PROJECT/secure-steganography/tests/test_payload.py) | Versioned JSON schema, Base64 serialization, canonical sorting, malformed payloads | 53 | ✅ Passed |
| [`tests/test_routes.py`](file:///c:/Users/USER/Desktop/CNS%20LAB%20PROJECT/secure-steganography/tests/test_routes.py) | Flask route endpoints, download security, integration pipelines, error responses | 22 | ✅ Passed |
| [`tests/test_security_audit.py`](file:///c:/Users/USER/Desktop/CNS%20LAB%20PROJECT/secure-steganography/tests/test_security_audit.py) | Security audit: GCM tampering, OOM defense, session privacy, path traversal, Unicode | 22 | ✅ Passed |
| [`tests/test_steganography.py`](file:///c:/Users/USER/Desktop/CNS%20LAB%20PROJECT/secure-steganography/tests/test_steganography.py) | Spatial 1-bit LSB embedding/extraction, big-endian header, image modes | 39 | ✅ Passed |
| [`tests/test_validators.py`](file:///c:/Users/USER/Desktop/CNS%20LAB%20PROJECT/secure-steganography/tests/test_validators.py) | Magic-byte checks, format enforcement (reject JPEG), size bounds, filename sanitization | 17 | ✅ Passed |
| **TOTAL VERIFIED SUITE** | **Complete System Automated Verification** | **211** | **211 Passed (100%)** |

---

## 22. Security Audit & Resilience Testing

The security suite (`tests/test_security_audit.py`) specifically verifies:
- **AES-GCM Tag Tampering:** Corrupting the final 16 bytes of ciphertext causes decryption to raise `DecryptionError`.
- **Nonce/Salt Tampering:** Modifying salt or nonce bits causes authentication failure.
- **SHA-256 Avalanche Effect:** Flipping a single bit in the message alters $> 40\%$ of the SHA-256 digest bits.
- **OOM Header Spoofing:** A crafted 32-bit header claiming excessive payload size is intercepted before memory allocation.
- **Session Cleanliness:** Flask session cookies contain zero cryptographic keys, plaintext passwords, or raw messages.

---

## 23. Step-by-Step Faculty Demonstration Script

### Demo 1: Successful Covert Transmission
1. Navigate to `http://127.0.0.1:5000/hide`.
2. Upload a sample PNG cover image.
3. Enter Secret Message: `[CONFIDENTIAL] Operation Alpha authorized at coordinates 28.6139N, 77.2090E.`
4. Enter Shared Passphrase: `SecurePass@2026`
5. Click **Encrypt & Hide Message**.
6. **Faculty Point:** Point out the **MSE ($< 0.01$)**, **PSNR ($> 60\text{ dB}$)**, and the **SHA-256 Digest**.
7. Download `stego_image.png`.

### Demo 2: Plaintext Extraction
1. Navigate to `http://127.0.0.1:5000/extract`.
2. Upload `stego_image.png`.
3. Enter Passphrase: `SecurePass@2026`.
4. Click **Extract & Decrypt Message**.
5. **Faculty Point:** Note the green verification badges ("SHA-256 Integrity Verified", "AES-GCM Authenticated") and the exact recovered message.

### Demo 3: Authentication Failure (Wrong Password)
1. On `/extract`, upload `stego_image.png`.
2. Enter incorrect passphrase: `WrongPassword123`.
3. Click **Extract & Decrypt Message**.
4. **Faculty Point:** The system safely rejects decryption without leaking any data or raising server errors.

### Demo 4: Bit-Level Tamper Detection
1. Tamper with a single pixel in `stego_image.png` using a hex editor or script.
2. Upload the altered image to `/extract` with the correct password.
3. **Faculty Point:** The SHA-256 integrity check immediately catches the modification and halts execution.

---

## 24. Beginner & Faculty User Guide (FAQ)

- **Q: What does "Hide Message" mean?**  
  *A:* It means taking your secret text, encrypting it with a password, and hiding those encrypted bits inside the pixels of an image.
- **Q: What does "Extract Message" mean?**  
  *A:* It means reading the hidden bits from a received stego image, verifying that the image was not tampered with, and decrypting the original text using the shared password.
- **Q: Is the password stored inside the image?**  
  *A:* **No.** The password is never stored anywhere in the image. Only a random cryptographic salt is stored.
- **Q: What file should be shared with the receiver?**  
  *A:* The generated **Stego PNG** file is shared via any standard channel (e.g. Email/Cloud Drive), and the password is shared separately.
- **Q: Why does the system reject JPEG images?**  
  *A:* JPEG uses lossy compression that alters pixel values and corrupts hidden LSB data. Lossless PNG and BMP preserve pixel data exactly.

---

## 25. Verified Technology Stack

- **Backend Web Framework:** Python 3.11+, Flask 3.0+
- **Production WSGI Server:** Gunicorn 21.2+
- **Cryptographic Library:** `cryptography` 42.0+ (PyCA)
- **Image Processing Engine:** Pillow (PIL) 9.5+
- **Mathematical & Matrix Library:** NumPy 1.26+
- **Automated Testing Framework:** Pytest 8.0+
- **Frontend Architecture:** Semantic HTML5, Vanilla CSS3 (Custom Dark Theme), Vanilla JavaScript (ES6+)

---

## 26. Repository File & Directory Structure

```
secure-steganography/
├── app.py                     # Application factory, top-level routes, & secure download handler
├── requirements.txt           # Verified project dependencies (Flask, Gunicorn, cryptography, Pillow, numpy, pytest)
├── README.md                  # Master academic & technical documentation
├── .gitignore                 # Excludes caches, virtualenvs, uploads, and outputs
├── config/
│   ├── __init__.py
│   └── settings.py            # Central configuration (16 MB upload limit, paths, PBKDF2 parameters)
├── crypto/
│   ├── __init__.py
│   ├── encryption.py          # PBKDF2-HMAC-SHA256 key derivation & AES-256-GCM authenticated encryption
│   └── hashing.py             # SHA-256 component hashing & constant-time validation
├── steganography/
│   ├── __init__.py
│   └── lsb.py                 # Spatial 1-bit RGB LSB embedding, extraction, & capacity calculation
├── utils/
│   ├── __init__.py
│   ├── payload.py             # Versioned JSON v1 payload builder, canonical serializer, & parser
│   ├── validators.py          # Magic-byte format check (PNG/BMP), size limits, & filename sanitization
│   └── image_analysis.py      # Mathematical MSE, PSNR, capacity info, & utilization calculations
├── routes/
│   ├── __init__.py            # Blueprint registration loader
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
│   └── .gitkeep               # Directory placeholder for temporary uploaded files
├── outputs/
│   └── .gitkeep               # Directory placeholder for generated stego images
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

## 27. Local Installation & Execution Guide

### Prerequisites
- Python 3.10, 3.11, or 3.12 installed.
- Git installed.

### Setup Commands (Windows PowerShell)
```powershell
# 1. Clone the repository
git clone https://github.com/PRUDHVI15-HUB/secure-steganography.git
cd secure-steganography

# 2. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run automated test suite (all 211 tests should pass)
python -m pytest tests/ -v

# 5. Start Flask development server
python app.py

# 6. Access the application in your browser:
# http://127.0.0.1:5000
```

---

## 28. Academic CNS Syllabus & Curriculum Mapping

| CNS Core Concept | Project Implementation | Laboratory Learning Outcome |
|---|---|---|
| **Symmetric Encryption** | AES-256 in Galois/Counter Mode | Understand modern block ciphers, key sizes, and AEAD modes. |
| **Key Derivation (KDF)** | PBKDF2-HMAC-SHA256 (600,000 rounds) | Understand password entropy, salts, and rainbow-table resistance. |
| **Cryptographic Hashing** | SHA-256 Digest over Container | Understand one-way hash functions, collision resistance, and avalanche effect. |
| **Message Authentication** | 16-byte GCM GMAC Tag | Understand ciphertext integrity and detection of bit-flipping attacks. |
| **Information Hiding** | Spatial 1-Bit RGB LSB Steganography | Understand steganographic capacity, imperceptibility, and cover media. |
| **Side-Channel Defense** | Constant-Time String Comparison | Understand timing attacks and secure comparison techniques. |
| **Signal Quality Metrics** | MSE and PSNR Formulation | Understand mathematical quantification of noise in image processing. |

---

## 29. Viva Voce Examination Preparation (22 Questions & Model Answers)

**Q1: What is the fundamental difference between cryptography and steganography?**  
> *Answer:* Cryptography scrambles a message to conceal its meaning (confidentiality), but leaves the communication visible. Steganography embeds the message into a carrier medium to conceal the very existence of the communication.

**Q2: Why did you choose AES-256-GCM instead of AES-CBC?**  
> *Answer:* AES-GCM is an Authenticated Encryption with Associated Data (AEAD) mode. It simultaneously provides confidentiality and authenticity via a 16-byte authentication tag, eliminating the need for a separate HMAC and preventing padding oracle attacks.

**Q3: What is the purpose of PBKDF2-HMAC-SHA256 in your project?**  
> *Answer:* Human passwords have low entropy. PBKDF2 stretches the password through 600,000 iterations of HMAC-SHA256 mixed with a 32-byte random salt to generate a uniform 256-bit symmetric key, making brute-force attacks computationally infeasible.

**Q4: Is the cryptographic salt secret?**  
> *Answer:* No. The salt does not need to be secret; its purpose is to ensure uniqueness and prevent precomputed rainbow-table attacks. It is stored publicly in the payload container.

**Q5: Why is a 12-byte nonce used in AES-GCM?**  
> *Answer:* 12 bytes (96 bits) is the standard NIST-recommended nonce size for GCM. It allows direct use in the counter mode without additional GHASH pre-processing. A fresh nonce is generated per encryption (`os.urandom(12)`) to prevent nonce reuse.

**Q6: What is the role of SHA-256 if AES-GCM already provides authentication?**  
> *Answer:* AES-GCM verifies authenticity during decryption. SHA-256 provides an independent educational container integrity check over $(salt \parallel nonce \parallel ciphertext)$, verifying the payload structure prior to executing cryptographic routines.

**Q7: How does spatial LSB steganography work?**  
> *Answer:* In a 24-bit RGB image, each pixel has 3 color bytes (Red, Green, Blue). The algorithm replaces the least significant bit (bit 0) of each channel with one payload bit. This modifies pixel values by at most $\pm 1 / 255$, which is imperceptible to human vision.

**Q8: What is the exact formula for image payload capacity?**  
> *Answer:* $\text{Capacity} = \lfloor (W \times H \times 3)/8 \rfloor - 4 \text{ bytes}$. The 3 accounts for 3 bits/pixel across RGB channels, dividing by 8 converts bits to bytes, and 4 bytes are reserved for the big-endian payload length header.

**Q9: Why does the system reject JPEG images?**  
> *Answer:* JPEG uses lossy compression based on the Discrete Cosine Transform (DCT) and quantization. Saving an image as JPEG alters pixel values and corrupts the least significant bits. PNG and BMP use lossless compression, preserving bits exactly.

**Q10: What are MSE and PSNR?**  
> *Answer:* Mean Squared Error (MSE) measures the average squared pixel difference between original and stego images (lower is better). Peak Signal-to-Noise Ratio (PSNR) measures reconstruction quality in decibels ($\text{PSNR} = 10 \log_{10}(255^2 / \text{MSE})$). Higher PSNR ($> 40\text{ dB}$) indicates high visual fidelity.

**Q11: What happens if an attacker enters the wrong password?**  
> *Answer:* The derived key will not match. During AES-GCM decryption, the 16-byte authentication tag verification fails, raising a `DecryptionError`. Zero plaintext is leaked.

**Q12: What happens if an attacker modifies a single pixel in the stego image?**  
> *Answer:* Modifying a pixel flips one or more payload bits. Upon extraction, the recalculated SHA-256 digest will not match the stored hash, and the AES-GCM tag verification will fail, halting decryption.

**Q13: How does the system defend against Out-Of-Memory (OOM) attacks?**  
> *Answer:* The LSB extractor reads the 4-byte payload length header and verifies that $\text{length} \le \text{Max Image Capacity}$ before allocating memory. If a malicious header claims a 4 GB payload on a 100 KB image, it is rejected immediately.

**Q14: How are files validated on upload?**  
> *Answer:* Pillow inspects the file's binary magic bytes (`Image.open()`) to verify it is genuinely a PNG or BMP file, ignoring spoofed file extensions.

**Q15: How are temporary files managed?**  
> *Answer:* Temporary uploads and generated stego images are automatically purged on server startup and on requests if they are older than 30 minutes.

**Q16: Is any sensitive data stored in Flask sessions?**  
> *Answer:* No. Sessions only store non-sensitive analysis metrics (e.g. MSE, PSNR, image dimensions). Passwords, derived keys, and plaintext messages are never stored in sessions or logs.

**Q17: Why is Base64 encoding used in the payload?**  
> *Answer:* JSON is a text format that cannot directly store raw binary bytes. Base64 encodes binary buffers (`salt`, `nonce`, `ciphertext`) into ASCII characters for safe JSON transport.

**Q18: What is constant-time comparison and why is it used?**  
> *Answer:* Standard string equality (`==`) exits early on the first mismatched character, leaking timing information. `hmac.compare_digest()` takes constant time regardless of where differences occur, preventing timing side-channel attacks.

**Q19: What does the 4-byte header in LSB embedding represent?**  
> *Answer:* It represents the length of the embedded payload in bytes, encoded as a 32-bit unsigned big-endian integer using `struct.pack(">I", length)`.

**Q20: What are the main limitations of this system?**  
> *Answer:* 1) Spatial LSB is fragile against resizing and lossy recompression; 2) Capacity is bounded by image dimensions; 3) Sequential LSB can be detected by statistical steganalysis (e.g., Chi-Square attack).

**Q21: How does the system achieve semantic security (IND-CPA)?**  
> *Answer:* Encrypting the same plaintext twice with the same password produces completely different ciphertexts and stego images because a fresh 32-byte salt and fresh 12-byte nonce are generated for every operation.

**Q22: How can this system be enhanced in the future?**  
> *Answer:* By implementing adaptive edge-based LSB embedding (using Sobel edge detection), transform-domain steganography (DWT/DCT), and asymmetric key encapsulation (RSA/ECC) for automated password exchange.

---

## 30. Current Implementation vs. Future Enhancements

```
┌────────────────────────────────────────┬────────────────────────────────────────┐
│         CURRENT IMPLEMENTATION         │          FUTURE ENHANCEMENTS           │
├────────────────────────────────────────┼────────────────────────────────────────┤
│ • AES-256-GCM authenticated encryption │ • Asymmetric RSA/ECC key exchange      │
│ • PBKDF2-HMAC-SHA256 (600k iterations) │ • Adaptive edge-based LSB embedding    │
│ • SHA-256 container integrity digest   │ • 2D Discrete Wavelet Transform (DWT)  │
│ • Spatial 1-bit RGB LSB embedding     │ • Steganographic PRNG pseudo-random key│
│ • Big-endian 4-byte length header      │ • Audio/Video carrier steganography    │
│ • Lossless PNG / BMP format validation │ • Automated steganalysis risk score    │
│ • MSE & PSNR image quality metrics     │ • Multi-file payload container support │
└────────────────────────────────────────┴────────────────────────────────────────┘
```

---

## 31. Screenshot & Visual Asset Documentation

*When preparing your laboratory presentation or project report, capture and embed the following screenshots from the running application (`http://127.0.0.1:5000`):*

- **[SCREENSHOT 1 — Home Dashboard (`/`)]**  
  *Shows:* Clean dark cybersecurity UI, action buttons for "Send / Hide Message" and "Receive / Extract Message", and the 2-party communication model cards.
- **[SCREENSHOT 2 — Send / Hide Page (`/hide`)]**  
  *Shows:* Two-column layout with file upload zone, live image preview, secret message textarea with UTF-8 byte counter, password inputs, and live capacity meter.
- **[SCREENSHOT 3 — Hide Success & Quality Metrics (`/hide` Results)]**  
  *Shows:* Success confirmation card, MSE value ($< 0.01$), PSNR value ($> 60\text{ dB}$), 64-character SHA-256 hash, and the "Download Stego PNG" button.
- **[SCREENSHOT 4 — Receive / Extract Page (`/extract`)]**  
  *Shows:* Stego image upload zone and shared password input field.
- **[SCREENSHOT 5 — Successful Decryption View (`/extract` Results)]**  
  *Shows:* Green status badges ("SHA-256 Verified", "AES-GCM Authenticated"), recovered plaintext message, and 1-click "Copy Text" button.
- **[SCREENSHOT 6 — Authentication Failure Alert (`/extract` Error)]**  
  *Shows:* Red alert banner demonstrating graceful rejection when an invalid password is provided.
- **[SCREENSHOT 7 — Security Analysis Dashboard (`/analysis`)]**  
  *Shows:* Recent operation KPI metrics and the on-demand cover vs. stego image quality comparison tool.
- **[SCREENSHOT 8 — Educational Reference Page (`/about`)]**  
  *Shows:* Cryptography vs. Steganography comparison table, AES-GCM technical breakdown, and mathematical formulas.

---

## 32. PowerPoint Presentation (PPT) Generation Guide (15 Slides)

*Use this exact slide-by-slide structure to build your project presentation:*

- **Slide 1: Title Slide**  
  - Title: *Secure Image Steganography: AES-256-GCM + SHA-256 + Spatial LSB*
  - Subtitle: *A Layered Covert Communication System for Cryptography & Network Security*
  - Presenters, Roll Numbers, Department of CSE, Faculty Guide.
- **Slide 2: Problem Statement & Motivation**  
  - The limitation of encryption alone (ciphertext signals secret activity).
  - The vulnerability of steganography alone (unencrypted payloads exposed upon extraction).
  - Solution: Defense-in-depth through combined authenticated cryptography and spatial steganography.
- **Slide 3: Proposed System Architecture**  
  - Sender and Receiver block diagrams.
  - Core stages: KDF $\rightarrow$ Authenticated Encryption $\rightarrow$ Digest $\rightarrow$ JSON $\rightarrow$ LSB Embed $\rightarrow$ LSB Extract $\rightarrow$ Decrypt.
- **Slide 4: Key Derivation (PBKDF2-HMAC-SHA256)**  
  - Why raw passwords cannot be used directly as AES keys.
  - 600,000 iterations + 32-byte cryptographic salt.
  - Defense against dictionary attacks and precomputed rainbow tables.
- **Slide 5: Authenticated Encryption (AES-256-GCM)**  
  - Why AES-GCM was selected over AES-CBC.
  - 256-bit symmetric key, 12-byte random nonce per encryption.
  - 16-byte authentication tag for bit-level tamper detection.
- **Slide 6: Container Integrity Hashing (SHA-256)**  
  - Role of SHA-256 over $(salt \parallel nonce \parallel ciphertext)$.
  - Constant-time verification (`hmac.compare_digest`).
  - Distinguishing container integrity from cryptographic authentication.
- **Slide 7: Versioned Payload Specification (JSON v1)**  
  - Base64 encoding of binary fields for safe JSON transport.
  - Canonical serialization with sorted keys.
  - Forward compatibility and schema enforcement.
- **Slide 8: Spatial 1-Bit RGB LSB Steganography**  
  - Modifying bit 0 of Red, Green, and Blue channels.
  - Bitwise formula: $(C \ \& \ 0\text{xFE}) \ | \ \text{bit}$.
  - 4-byte big-endian length prefix.
- **Slide 9: Steganographic Capacity & Format Validation**  
  - Capacity formula: $\lfloor (W \times H \times 3)/8 \rfloor - 4\text{ bytes}$.
  - Why PNG/BMP (lossless) is required and JPEG (lossy) is rejected.
  - Binary magic-byte inspection via Pillow.
- **Slide 10: Image Quality Metrics (MSE & PSNR)**  
  - Mathematical formulation of MSE and PSNR.
  - Experimental results: $\text{MSE} < 0.01$, $\text{PSNR} > 60\text{ dB}$.
  - Proof of visual imperceptibility.
- **Slide 11: Defensive Web Engineering & Hardening**  
  - Zero session-based secret storage.
  - Path-traversal defense on download endpoints.
  - Out-of-Memory (OOM) header spoofing defense.
  - Automatic temporary file cleanup.
- **Slide 12: Automated Testing & Security Audit**  
  - 211 automated test cases across 8 test suites with 100% pass rate.
  - Security audit tests: Tag tampering, nonce manipulation, avalanche effect, session privacy.
- **Slide 13: Live Demonstration Workflow**  
  - Hide workflow, Stego PNG download, extraction with correct password, and rejection with wrong password.
- **Slide 14: Limitations & Future Enhancements**  
  - Fragility under lossy compression and statistical steganalysis vulnerability.
  - Future scope: Adaptive edge embedding, DWT transform domain, and RSA/ECC key exchange.
- **Slide 15: Conclusion & References**  
  - Summary of contributions, curriculum mapping, and thank you / Q&A.

---

## 33. Academic Project Report Chapter Outline (21 Sections)

*Use this comprehensive chapter structure for your formal B.Tech laboratory report / project documentation:*

1. **Cover Page & Certificate of Originality**
2. **Academic Abstract & Keywords**
3. **Chapter 1: Introduction** (Background, Motivation, Cryptography vs. Steganography)
4. **Chapter 2: Literature Review** (Evolution of Steganography, Symmetric Ciphers, Password Hashing Standards)
5. **Chapter 3: Problem Statement & Objectives**
6. **Chapter 4: Theoretical & Mathematical Foundation** (AES-GCM, PBKDF2, SHA-256, LSB, MSE, PSNR)
7. **Chapter 5: System Architecture & Design** (Block Diagrams, Data Flow Pipelines)
8. **Chapter 6: Cryptographic Implementation** (`crypto/encryption.py`, `crypto/hashing.py`)
9. **Chapter 7: Steganographic Implementation** (`steganography/lsb.py`)
10. **Chapter 8: Payload & Validation Layer** (`utils/payload.py`, `utils/validators.py`)
11. **Chapter 9: Image Quality Analysis Engine** (`utils/image_analysis.py`)
12. **Chapter 10: Web Application & Interface Design** (Flask Blueprints, Jinja2 Templates, Vanilla CSS/JS)
13. **Chapter 11: Security Engineering & Web Hardening** (Session Privacy, OOM Defense, Path Traversal)
14. **Chapter 12: Experimental Results & Performance Evaluation** (MSE/PSNR Tables, Capacity Graphs)
15. **Chapter 13: Failure Handling & Threat Model Verification** (Tamper Detection, Wrong Password Handling)
16. **Chapter 14: Automated Testing & Verification** (211 Unit, Integration, and Security Tests)
17. **Chapter 15: User Manual & Operational Guide** (Step-by-Step Instructions)
18. **Chapter 16: Curriculum Mapping & Educational Value** (CNS Syllabus Topics)
19. **Chapter 17: Limitations & Environmental Constraints**
20. **Chapter 18: Conclusion & Future Scope**
21. **References & Appendix** (Standards, Source Code Listings)

---

## 34. Team Handoff & Collaboration Notes

> ### 📢 Important Instructions for Teammates:
> 1. **The Codebase is 100% Complete & Verified:** Do not modify any backend Python files, cryptographic logic, or routes while preparing reports or presentations.
> 2. **Use this README as the Single Source of Truth:** All formulas, parameter counts (600,000 PBKDF2 iterations, 32-byte salt, 12-byte nonce, 16-byte GCM tag), and test totals (211 passed) in this README reflect the real, verified code.
> 3. **Capturing Screenshots:** Run `python app.py` locally and capture actual screenshots from `http://127.0.0.1:5000` for your PPT and report.
> 4. **Manual Fields to Fill:** In Section 1, update your College Name, Department, Team Member Names, Roll Numbers, Faculty Guide, and Submission Date.

---

## 35. Final Project Verification Status

| System Component | Implementation Module | Automated Tests | Verification Status |
|---|---|:---:|:---:|
| **Key Derivation** | `crypto/encryption.py` | 19 tests | ✅ **COMPLETE & VERIFIED** |
| **AES-256-GCM Encryption** | `crypto/encryption.py` | 19 tests | ✅ **COMPLETE & VERIFIED** |
| **SHA-256 Integrity Digest** | `crypto/hashing.py` | 25 tests | ✅ **COMPLETE & VERIFIED** |
| **Versioned JSON Payload** | `utils/payload.py` | 53 tests | ✅ **COMPLETE & VERIFIED** |
| **Spatial LSB Steganography** | `steganography/lsb.py` | 39 tests | ✅ **COMPLETE & VERIFIED** |
| **Format & Magic Validation** | `utils/validators.py` | 17 tests | ✅ **COMPLETE & VERIFIED** |
| **MSE & PSNR Image Analysis** | `utils/image_analysis.py` | 14 tests | ✅ **COMPLETE & VERIFIED** |
| **Flask Web Routes & Handlers** | `routes/`, `app.py` | 22 tests | ✅ **COMPLETE & VERIFIED** |
| **Security Audit & Defense** | `tests/test_security_audit.py` | 22 tests | ✅ **COMPLETE & VERIFIED** |
| **Frontend UI / JavaScript** | `templates/`, `static/` | Verified in Browser | ✅ **COMPLETE & VERIFIED** |
| **TOTAL AUTOMATED SUITE** | **Complete System** | **211 Tests** | ✅ **211/211 PASSED (100%)** |
