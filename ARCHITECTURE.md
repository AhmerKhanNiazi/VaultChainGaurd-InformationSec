# VaultChain Guard — Technical Architecture & Specifications

This document outlines the cryptographic design, container specification, security threat model, and user interface engineering of **VaultChain Guard**.

---

## 1. Cryptographic Security Model

VaultChain Guard implements a multi-tier defense-in-depth architecture adhering to modern NIST and OWASP standards.

```
+---------------------------------------------------------------------------------+
|                               ENCRYPTION PIPELINE                               |
|                                                                                 |
|   Target File                                                                   |
|       |                                                                         |
|       +---> [ SHA-256 Digest ] ------------------> [ RSA-PSS Sign ]             |
|       |                                                    |                    |
|       +---> [ DES-CBC Encrypt ]                            |                    |
|                ^          |                                |                    |
|  Hardware      |          v                                v                    |
|  RNG Key ------+---> [ RSA-OAEP Wrap ]              Digital Signature           |
|  (64-bit)                 |                                |                    |
|                           v                                v                    |
|               Wrapped Session Key                          |                    |
|                           |                                |                    |
|                           +--------------+-----------------+                    |
|                                          |                                      |
|                                          v                                      |
|                             Encapsulate into .vsec                              |
+---------------------------------------------------------------------------------+
```

### 1.1 Symmetric Layer (DES-CBC)
- **Algorithm:** Data Encryption Standard in Cipher Block Chaining mode (`DES-CBC`).
- **Key Size:** 64-bit (56 effective key bits + 8 parity bits).
- **IV Size:** 64-bit hardware-random initialization vector via `os.urandom(8)`.
- **Padding:** PKCS#7 standard (block size: 8 bytes).

### 1.2 Asymmetric Key Encapsulation (RSA-2048 OAEP)
- **Algorithm:** RSA with 2048-bit modulus and public exponent $e = 65537$.
- **Padding:** Optimal Asymmetric Encryption Padding (`OAEP`).
- **Hash Functions:** Mask Generation Function MGF1 parameterized with SHA-256.
- **Security:** Protects against chosen-ciphertext attacks (IND-CCA2 security).

### 1.3 Authenticity & Integrity Layer (SHA-256 with RSA-PSS)
- **Digest Algorithm:** Secure Hash Algorithm 256-bit (`SHA-256`).
- **Signature Padding:** Probabilistic Signature Scheme (`PSS`) with maximum salt length.
- **Guarantee:** Guarantees non-repudiation, tamper-detection, and payload authenticity.

---

## 2. `.vsec` Binary Container Specification

A `.vsec` file is an atomic cryptographic container structured as follows:

| Field | Size | Data Type | Description |
|---|---|---|---|
| Magic Header | 6 Bytes | ASCII | `VSEC01` magic identifier |
| Metadata Size | 4 Bytes | Big-Endian uint32 | Byte length $N$ of JSON metadata block |
| Metadata Block | $N$ Bytes | UTF-8 JSON | Structural payload parameters, hashes, and offsets |
| Wrapped Key | 256 Bytes | Binary | RSA-2048 OAEP wrapped DES session key |
| Digital Signature | 256 Bytes | Binary | RSA-PSS signature of the original file SHA-256 digest |
| Ciphertext | Variable | Binary | DES-CBC encrypted payload with PKCS#7 padding |

### Metadata Schema
```json
{
  "original_filename": "confidential_report.pdf",
  "timestamp": "2026-11-10T17:15:00.123456",
  "file_hash_hex": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "encrypted_key_len": 256,
  "signature_len": 256,
  "ciphertext_len": 65536,
  "iv_hex": "3a8f1b0c9e2d4f5a"
}
```

---

## 3. Anti-Tamper Verification Protocol

When a `.vsec` container is verified, the system executes a 4-checkpoint pipeline:

1. **Checkpoint 1 — Container Magic & Format:** Confirms `VSEC01` header and parses JSON metadata boundaries.
2. **Checkpoint 2 — Key Decapsulation:** Uses the receiver's private RSA key with OAEP padding to unwrap the 64-bit DES session key and 64-bit IV.
3. **Checkpoint 3 — Ciphertext Decryption:** Reverses DES-CBC encryption and removes PKCS#7 padding to extract the raw plaintext.
4. **Checkpoint 4 — Dual Integrity Audit:**
   - Recomputes SHA-256 digest of decrypted bytes and compares it against metadata `file_hash_hex`.
   - Uses the sender's public RSA key to verify the RSA-PSS digital signature.
   - If either check fails, verification aborts, setting critical alerts and identifying bit flips.

---

## 4. UI Architecture & Liquidmorphism

VaultChain Guard features a custom-built GUI framework powered by CustomTkinter:

- **Obsidian Indigo Palette:**
  - Root: `#050813`
  - Sidebar: `#080e1d`
  - Cards: `#0c152a` (with `#111f3c` on hover)
  - Neon Accents: Cyan `#00f0ff`, Green `#00ff9d`, Red `#ff3366`
- **Responsive Layout Architecture:**
  - Employs proportional `grid_columnconfigure` (55% / 45% on Vault, 50% / 50% on Radar) to prevent horizontal widget crushing.
  - Page-specific scrollable isolation: Main pages are zero-scroll, while logs and large brute-force candidate lists utilize bounded frames.
- **Hardware-Decoupled Animations:**
  - 50ms radar sweeps, canvas vector meters, and heartbeat alert pulses running via non-blocking Tkinter `after` timers.
