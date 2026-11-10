# VaultChain Guard — Enterprise Security Suite

![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python)
![CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter%205.2-cyan)
![Cryptography](https://img.shields.io/badge/Crypto-PyCA%2Fcryptography-00ff9d)
![Architecture](https://img.shields.io/badge/Cipher-DES--CBC%20%7C%20RSA--2048%20%7C%20SHA--256-ff3366)
![Status](https://img.shields.io/badge/Build-Production--Ready-brightgreen)

**VaultChain Guard** is a next-generation desktop cryptographic security application engineered with a deep-obsidian **liquidmorphic GUI**. It provides end-to-end data encapsulation, real-time binary integrity verification with radar visualization, classical cryptanalysis tools, and automated HTTP security posture auditing.

---

## 🛡️ Core Security Modules

### 1. 🔒 Hybrid Cryptographic Vault
* **Symmetric Payload Encryption:** Encrypts any binary, media, or document file using **DES-CBC** with PKCS7 padding and a hardware-random 64-bit session key and initialization vector (IV).
* **Asymmetric Session Key Encapsulation:** Encapsulates the ephemeral DES session key using **RSA-2048** with Optimal Asymmetric Encryption Padding (**OAEP** / MGF1 / SHA-256).
* **Digital Signature & Non-Repudiation:** Computes a **SHA-256** digest of the raw payload and seals it with **RSA-PSS** signature padding.
* **Encapsulated Container Format (`.vsec`):** Packs the encrypted payload, OAEP-wrapped key, digital signature, and JSON metadata into a unified secure binary format.
* **Keypair Certificate Export:** One-click export of generated public and private keypairs in PEM certificate format.

### 2. 🛡️ Anti-Tamper Verification Radar
* **Live Radar Sweep:** Custom animated sweep beam displaying real-time integrity checkpoints.
* **4-Stage Verification Progression:**
  1. Binary Magic Bytes (`VSEC01`) & JSON Metadata Extraction.
  2. RSA-OAEP Session Key Unwrapping with the private key.
  3. DES-CBC Ciphertext Decryption & PKCS7 Unpadding.
  4. SHA-256 Digest Matching & RSA-PSS Digital Signature Verification.
* **Hex Tamper Simulation Engine:** Programmatically injects XOR `0xFF` single-byte bit-flips directly into the binary container to simulate MITM tampering and attacks.
* **Alert Breathing Protocol:** Dynamic liquidmorphic pulsing alert feedback in real-time when tampering or signature corruption is identified.
* **Payload Restoration:** Authenticated decryption and payload recovery for verified containers.

### 3. ⚙️ Classical Cryptanalysis & Cipher Sandbox
* **Caesar Workstation:**
  * Interactive shift parameter slider (1–25).
  * Automated **Brute-Force Radar** evaluating all 25 shift permutations.
  * Statistical **Chi-Squared ($\chi^2$) distribution scoring** comparing candidate letter frequencies to standard English distributions.
  * Real-time animated **Letter Frequency Bars** visualizing distribution deltas.
* **Playfair 5x5 Workstation:**
  * Dynamic 5×5 polygraphic matrix generator with automatic `I/J` consolidation.
  * Sequential cascade illumination animation highlighting unique keyword coordinates.
  * Strict polygraphic encryption and decryption transformations.

### 4. 🌐 Web Browser & Header Security Inspector
* **Automated Defensive Header Evaluation:** Inspects target hosts for essential OWASP hardening headers:
  * `Strict-Transport-Security` (HSTS)
  * `Content-Security-Policy` (CSP)
  * `X-Frame-Options` (Clickjacking defense)
  * `X-Content-Type-Options` (MIME sniffing prevention)
  * `Referrer-Policy` & `Permissions-Policy`
* **Security Speedometer:** Custom vectorized canvas gauge rendering dynamic score-based arcs and letter grades (`A+` to `F`).
* **Cookie Telemetry:** Inspects response cookies for critical flags: `HttpOnly`, `Secure`, and `SameSite`.

### 5. 📋 Enterprise Audit Log Console
* **Real-Time Telemetry:** Timestamped, thread-safe streaming of hardware events, key allocations, and verification states.
* **Severity Filtering:** One-click toggle filters for `INFO`, `SUCCESS`, `WARNING`, `ERROR`, and `CRITICAL`.
* **Exportable Reports:** Export raw text audit logs with formatted report banners for external compliance reporting.

---

## 📐 `.vsec` Binary Container Architecture

The custom `.vsec` (VaultChain Secure) container format enforces atomic structural verification:

```
+-------------------------------------------------------------+
| MAGIC BYTES: 'VSEC01' (6 bytes ASCII)                       |
+-------------------------------------------------------------+
| METADATA LENGTH: 4 bytes (Big-Endian uint32)                |
+-------------------------------------------------------------+
| JSON METADATA:                                              |
| {                                                           |
|   "original_filename": string,                              |
|   "timestamp": ISO-8601 string,                             |
|   "file_hash_hex": SHA-256 hex string,                      |
|   "encrypted_key_len": int,                                 |
|   "signature_len": int,                                     |
|   "ciphertext_len": int,                                    |
|   "iv_hex": 16-hex characters                               |
| }                                                           |
+-------------------------------------------------------------+
| RSA-OAEP ENCRYPTED DES KEY (256 bytes)                      |
+-------------------------------------------------------------+
| RSA-PSS DIGITAL SIGNATURE (256 bytes)                       |
+-------------------------------------------------------------+
| DES-CBC ENCRYPTED CIPHERTEXT (Variable bytes, PKCS7 padded) |
+-------------------------------------------------------------+
```

---

## 🚀 Installation & Quickstart

### Prerequisites
* **Python 3.10+**
* Windows 10/11, macOS, or Linux

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AhmerKhanNiazi/VaultChainGaurd-InformationSec.git
   cd VaultChainGaurd-InformationSec
   ```

2. **Create and activate a virtual environment (recommended):**
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # macOS/Linux:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the application:**
   ```bash
   python main.py
   ```

---

## 🗂️ Project Directory Structure

```
VaultChain Guard/
├── core/
│   ├── __init__.py
│   ├── crypto_engine.py      # DES-CBC, RSA-2048 OAEP, SHA-256 PSS & container logic
│   ├── cipher_sandbox.py     # Caesar, Chi-squared frequency analysis, Playfair matrix
│   └── browser_audit.py      # HTTP defense header inspection & OWASP scoring
├── ui/
│   ├── __init__.py
│   ├── theme.py              # Obsidian-indigo liquidmorphism color palette & fonts
│   ├── components.py         # GlassCard, NavPill, PulsingBeacon, RadarScanner
│   └── main_window.py        # Master responsive layout, telemetry pipelines & views
├── .gitignore
├── requirements.txt
├── ARCHITECTURE.md           # In-depth cryptographic & GUI architecture specification
└── README.md
```

---

## 🔬 Technologies & Libraries

* **GUI Framework:** [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) & Tkinter Canvas Vector Graphics
* **Cryptographic Primitives:** [PyCA / Cryptography](https://cryptography.io)
* **Networking & Audit:** Requests (HTTP response inspection)
* **Design Philosophy:** Obsidian-indigo palette, responsive proportional grids, high-frequency radar animations, zero-lag timer decoupling.

---

## 👤 Author & Academic Context

* **Project:** Network & Information Security Laboratory Suite
* **Author:** Ahmer Khan Niazi
* **Institution:** Iqra University

---

## 📄 License
This project is licensed under the MIT License — see the repository for details.
