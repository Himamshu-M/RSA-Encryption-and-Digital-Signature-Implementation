# 🔐 RSA Encryption & Digital Signature — From Scratch

A pure Python implementation of RSA-2048 encryption, decryption, and digital
signatures built entirely from scratch — no cryptographic libraries used.
Includes OAEP padding, Miller-Rabin primality testing, CRT-optimized
decryption, and performance benchmarking.

> **Author:** Himanshu Patel | IIIT Kalyani
> **Language:** Python 3.8+
> **Date:** February 2026

---

## 📁 Project Structure

```
rsa_project/
├── rsa_core.py          # RSA key generation, raw encrypt/decrypt primitives
├── oaep.py              # OAEP padding scheme (MGF1, encode, decode)
├── digital_signature.py # Sign and verify messages using SHA-256 + RSA
├── benchmark.py         # Performance benchmarking for all operations
└── main.py              # End-to-end demo runner
```

---

## ✨ Features

- **2048-bit RSA Key Generation** using Miller-Rabin probabilistic primality test (k=40 rounds)
- **OAEP Padding** (RFC 3447 §7.1) with SHA-256 and MGF1 — resistant to chosen-ciphertext attacks
- **CRT-Optimized Decryption** — ~4× faster than naive modular exponentiation using Chinese Remainder Theorem
- **Digital Signatures** — sign and verify messages using SHA-256 hashing + RSA private key operation
- **Performance Benchmarking** — measures encryption, decryption, signing, and verification latency
- **No third-party crypto libraries** — only Python built-ins (os, hashlib, random)

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- No external dependencies required

### Installation

```bash
git clone https://github.com/Himamshu-M/RSA_ATTACK.git
cd RSA_ATTACK
```

### Run the Demo

```bash
python main.py
```

**Sample Output:**
```
[*] Generating 2048-bit RSA key pair...
[+] Key generation complete in 1.842s

Original  : b'Hello, RSA from scratch!'
Decrypted : b'Hello, RSA from scratch!'
Match     : True

Signature valid : True
Tamper test     : False
```

### Run Benchmarks

```bash
python benchmark.py
```

**Sample Benchmark Output:**
```
─── RSA-2048 Benchmark Results ───
  Encryption  :  1.24 ms/op
  Decryption  : 18.73 ms/op  (CRT optimized)
  Signing     : 19.02 ms/op
  Verification:  1.31 ms/op
  Correctness : PASS
```

---

## 🧮 Technical Design

### Key Generation
1. Generate two random 1024-bit primes p and q using os.urandom() seeded candidates
2. Validate each candidate with Miller-Rabin (40 rounds → error probability < 4^-40)
3. Compute n = p × q, φ(n) = (p-1)(q-1)
4. Set public exponent e = 65537 (standard Fermat prime)
5. Compute private exponent d = e⁻¹ mod φ(n) via Extended Euclidean Algorithm

### OAEP Padding (RFC 3447)
- Encode: Hash label with SHA-256 → build data block → XOR with MGF1-derived masks using random seed
- Decode: Reverse masks → verify label hash → extract message
- Max message size: 256 - 2×32 - 2 = 190 bytes per operation for 2048-bit keys

### CRT Optimization
Decryption uses precomputed values dp, dq, q_inv to split one large exponentiation into two smaller ones:

  m1 = c^dp mod p
  m2 = c^dq mod q
  m  = m2 + q × ((q_inv × (m1 - m2)) mod p)

### Digital Signature Scheme
- Sign:   SHA-256(message) → PKCS#1 v1.5 padding → private key RSA operation
- Verify: Public key RSA operation → recover digest → compare with SHA-256(message)

---

## ⚠️ Security Disclaimer

This implementation is intended for **educational purposes only**.
For production systems, use audited libraries such as:
- cryptography (https://cryptography.io/)
- PyCryptodome (https://pycryptodome.readthedocs.io/)
- OpenSSL

Do NOT use this code to protect real sensitive data.

---

## 📚 References

- RFC 3447 — PKCS #1 v2.1: RSA Cryptography Standard
  https://datatracker.ietf.org/doc/html/rfc3447
- Rivest, Shamir, Adleman — A Method for Obtaining Digital Signatures
  and Public-Key Cryptosystems (1978)
- Miller-Rabin Primality Test — Rabin, M. O. (1980)

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.
