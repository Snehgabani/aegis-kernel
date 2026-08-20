# 🛡️ Security Capabilities & Supply Chain Transparency Report

> **Compliance Status**: Verified against [OpenSSF Best Practices (Project #14173)](https://www.bestpractices.dev/en/projects/14173/passing), [Socket.dev Package Health](https://socket.dev/npm/package/@aegis-kernel/core), and [SLSA Level 3](https://slsa.dev).

---

## 1. Overview & Trust Model

Aegis Invariant Kernel is a **zero-trust, deterministic safety layer** designed for high-assurance AI agent environments. In compliance with modern software supply chain security standards (OpenSSF, Socket.dev, NIST AI RMF), this document provides full transparency into all runtime capabilities, system permissions, and third-party dependencies used by `@aegis-kernel/core`.

---

## 2. Declared Runtime Capabilities & Permission Scopes

Socket.dev and static analysis engines analyze package capabilities to detect latent risks. Below is the comprehensive declaration and rationale for all system capabilities used by `@aegis-kernel/core`:

| Capability | Socket Alert Level | Purpose & Exact Usage in Aegis Kernel | Is it Network Isolated? |
| :--- | :--- | :--- | :--- |
| **Network Access** | `Informational / Warn` | Used strictly for **optional, user-configured** capabilities:<br>1. Remote Rule Pack Sync (`AegisDynamicSync`)<br>2. SIEM / Webhook alerts (`AegisWebhookBot`, OpenTelemetry exporter)<br>3. Threat Intelligence Feed updates | **Yes by default**. The core evaluation engine (`evaluate()`, `intercept()`) is 100% offline and in-process (<0.25ms). Outbound HTTP requests only occur if explicit remote endpoints are configured. |
| **Filesystem Access** | `Informational` | Reads declarative `.aegis/packs/*.yaml` rule definitions and local configuration from disk via `fs.readFileSync`. Never writes to host filesystem without explicit user command (`aegis init`). | **Read-only** during evaluation. Fully isolated. |
| **Environment Variables** | `Informational` | Reads `process.env.AEGIS_*` (e.g. `AEGIS_MODE`, `AEGIS_SECRET_KEY`, `AEGIS_TELEMETRY`) to allow zero-config environment overrides in container and serverless deployments. | Read-only access to `AEGIS_*` prefixed variables. |
| **Debug / Stack Traces** | `Informational` | Captures stack frame context during forensic trace logging (`AegisForensicTrace`) to pinpoint the exact caller line where an injection or invariant violation occurred. | In-memory only; no external exfiltration. |
| **AST Parser Execution** | `Informational` | Parses complex SQL dialects (PostgreSQL, MySQL, SQLite, T-SQL) into abstract syntax trees for deterministic structure validation. | Sandboxed in-memory parsing. |

---

## 3. Dependency Transparency & Audit

### Dependency 1: `node-sql-parser`
* **Role**: Multi-dialect SQL AST generation and query structure parsing.
* **Why Socket.dev flags it**:
  - *Obfuscated code flag*: `node-sql-parser` is compiled using PEG.js / ANTLR parser generators. These generators produce dense, machine-generated lexical transition lookup tables which heuristic static scanners flag as "obfuscated code" (a known false positive for grammar/parser compilers).
  - *Dynamic code execution / eval flag*: PEG.js runtime uses constructor-level code evaluation to instantiate parser rules efficiently.
* **Safety Verification**:
  - `node-sql-parser` is an established, widely used open-source library with >1.5M weekly downloads.
  - Aegis executes SQL parsing in-memory against unexecuted string literals without passing data to database drivers.
  - Full fallback parsing and regex/homoglyph/tautology analysis operate independently of the AST parser.

### Dependency 2: `js-yaml`
* **Role**: Parsing declarative YAML rule packs (`.aegis/packs/*.yaml`).
* **Safety Verification**: Uses safe schema parsing (`DEFAULT_SCHEMA`) preventing arbitrary object instantiation.

### Dependency 3: `ajv`
* **Role**: Validates JSON schema invariant parameters against strict JSON Schema Draft 7 specifications.
* **Safety Verification**: Compiles validation schemas in strict mode with prototype pollution guards.

---

## 4. Zero Transitive Vulnerability Invariant

* **Rust Crate (`packages/rust`)**: Uses pure-Rust zero-dependency cryptographic engines for SHA-256 and HMAC-SHA256, eliminating all transitive crates (`block-buffer`, `digest`, `sha2`, `hmac`) and achieving **0 CVEs**.
* **Container Images (`Dockerfile`, `deploy/helm`)**:
  - Base: `node:22-alpine` with automated `apk upgrade --no-cache`.
  - Non-root user: `aegis:10001:10001`.
  - Security context: `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`.
  - OpenSSL: Verified `>= 3.5.7-r0` (0 open container vulnerabilities).

---

## 5. Summary & Verification

| Security Domain | Standard | Compliance Status |
| :--- | :--- | :--- |
| **OpenSSF Best Practices** | CII / OpenSSF Badge | **Passing Badge #14173** (67/67 criteria met) |
| **Static Security Analysis** | Socket.dev / Snyk / CodeQL | **0 High / 0 Critical Vulnerabilities** |
| **Container Hardening** | Hadolint / CIS Kubernetes Benchmark | **100% Clean / 0 Privilege Escalation** |
| **Cryptographic Proof** | AICPA SSAE 18 & Merkle Tree Chains | **Ed25519 & HMAC-SHA256 Zero-Drift Verifiable** |
