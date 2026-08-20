# OpenSSF Best Practices Badge (CII Badge) — Criteria Attestation & Evidence

**Project**: Aegis Invariant Kernel (`aegis-kernel`)  
**Badge Project ID**: [10182](https://www.bestpractices.dev/en/projects/10182)  
**Standard**: OpenSSF Best Practices Badge (Passing / Silver Level)  
**Date**: August 2026

---

## 1. Documentation Criteria

### `[documentation_basics]` — Basic Documentation
- **Status**: **MET**
- **Evidence & Details**:
  - **Installation & Getting Started**: [`docs/GETTING_STARTED.md`](../GETTING_STARTED.md) provides complete instructions on installing (`npm`, `pip`, Go, Rust, Docker) and starting the software in TypeScript, Python, and MCP environments.
  - **Tutorials with Examples**: [`docs/GETTING_STARTED.md`](../GETTING_STARTED.md) includes 3 concrete tutorials (SQL injection defense, financial spend limits, PII redaction).
  - **Secure Usage (What to Do and What NOT to Do)**: [`docs/SECURITY_USER_GUIDE.md`](../SECURITY_USER_GUIDE.md) details operational dos (enforce mode, fail-closed, least-privilege DB roles, per-session salt vaults) and don'ts (no raw regexes, no disabling invariants for sub-agents).

### `[documentation_interface]` — Interface Reference Documentation
- **Status**: **MET**
- **Evidence & Details**:
  - **API Reference**: [`docs/API_REFERENCE.md`](../API_REFERENCE.md) provides exhaustive reference documentation covering:
    - Core library classes (`AegisEngine`, `PiiTokenVault`, `AegisStreamInterceptor`, `AegisBiscuitToken`), their constructor parameters, method signatures, inputs (`ToolCall`), and outputs (`AegisResult`, `AegisViolation`).
    - Gateway HTTP REST interface (`POST /v1/evaluate`, `POST /v1/tokenize`, `POST /v1/detokenize`, `GET /health`).
    - Standalone CLI commands, options, and parameters (`aegis test`, `aegis scan`, `aegis eval`, `aegis benchmark`, `aegis replay`, `aegis pack`).
    - Python SDK (`@aegis_guard` decorator, `PythonStateChecker`, `PythonPiiTokenVault`).

---

## 2. Cryptographic Security Criteria

### `[crypto_floss]` — FLOSS Cryptography
- **Status**: **MET**
- **Evidence & Details**:
  - All cryptographic functionality in the project is implemented using standard Free/Libre/Open Source Software (FLOSS):
    - TypeScript/Node.js: Node.js standard library `node:crypto` (OpenSSL/BoringSSL, FLOSS).
    - Python SDK: Standard library `hashlib`, `hmac`, `secrets` (FLOSS).
    - Rust Crate: `sha2`, `hmac`, `ed25519-dalek` (MIT / Apache-2.0 FLOSS).
    - Go SDK: Standard library `crypto/sha256`, `crypto/hmac`, `crypto/rand` (BSD FLOSS).
  - Zero proprietary or closed-source cryptographic libraries are used.

### `[crypto_keylength]` — NIST 2030+ Minimum Key Lengths
- **Status**: **MET**
- **Evidence & Details**:
  - All cryptographic mechanisms within Aegis use key lengths meeting or exceeding NIST SP 800-57 guidelines through 2030+:
    - **Hashes & HMACs**: SHA-256 (256 bits >= NIST 224-bit minimum) and HMAC-SHA256 (256-bit key >= NIST 112-bit symmetric minimum).
    - **Asymmetric Signatures**: Ed25519 (256-bit elliptic curve >= NIST 224-bit minimum) for Biscuit capability tokens ([`packages/core/src/a2a/biscuit-token.ts`](../../packages/core/src/a2a/biscuit-token.ts)).
    - **Symmetric Salts**: 128-bit and 256-bit cryptographically secure random salts.
  - Insecure algorithms (MD5, SHA-1, DES, RSA-1024) are completely unsupported and disabled.

### `[crypto_password_storage]` — Password Storage
- **Status**: **N/A (Not Applicable)**
- **Evidence & Details**:
  - Aegis Invariant Kernel is an in-process tool-call clearance engine and API security middleware. The project does **not** store passwords for authentication of external users (inbound user authentication).
  - For secret masking, Aegis utilizes ephemeral salted HMAC tokenization (`PiiTokenVault`).

### `[crypto_random]` — Cryptographically Secure Random Number Generators (CSPRNG)
- **Status**: **MET**
- **Evidence & Details**:
  - All cryptographic keys, nonces, tokens, and salts are generated exclusively using operating-system backed CSPRNGs:
    - Node.js: `crypto.randomBytes()`, `crypto.randomUUID()` (OpenSSL CSPRNG / `/dev/urandom`).
    - Python: `secrets.token_hex()`, `secrets.token_bytes()`, `os.urandom()`.
    - Go: `crypto/rand.Read()`.
    - Rust: OS CSPRNG.
  - **Zero calls** to insecure random generators (`Math.random()` or Python `random.random()`) exist in the codebase.
