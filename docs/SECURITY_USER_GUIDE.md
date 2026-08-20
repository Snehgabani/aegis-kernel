# Aegis Invariant Kernel — Security User Guide

> **Guidelines on how to deploy and operate Aegis Invariant Kernel securely in production agent architectures (What to do and what NOT to do).**

---

## 1. Security Architecture Overview

Aegis is an in-process deterministic clearance kernel designed to sit between autonomous LLM agent planners and physical tool executors (databases, APIs, payment gateways). To achieve maximum security resilience, follow the operational principles below.

---

## 2. What to DO (Security Best Practices)

### ✅ 1. Always Run in `enforce` Mode in Production
- **DO**: Configure `mode: 'enforce'` for production environments so that invariant breaches actively block the proposed tool execution.
- **DO**: Use `mode: 'audit'` only during staging, canary rollouts, or initial shadow testing when profiling benign traffic baseline behavior.

### ✅ 2. Maintain Defense-in-Depth
- **DO**: Pair Aegis with database least-privilege permissions (e.g., read-only database credentials for read-only query tools). Aegis is a safety clearance gateway, not a replacement for database roles, network firewalls, or operating system sandboxes.

### ✅ 3. Enforce Fail-Closed Default Policies
- **DO**: Keep `failPolicy: 'fail-closed'` (the default). If an internal parsing error, malformed AST, or timeout occurs, the tool call must be rejected to prevent fail-open bypasses.

### ✅ 4. Use Per-Session Salted PII Vaults
- **DO**: Initialize `PiiTokenVault` per conversation session. The vault generates a 128-bit cryptographically secure random salt (`crypto.randomBytes(16)`) per session, ensuring tokenized hashes cannot be correlated across unrelated agent interactions.

### ✅ 5. Regularly Ingest Pre-Compiled Rule Packs
- **DO**: Enable the standard rule packs (`@aegis/sql-guard`, `@aegis/data-guard`, `@aegis/safety-guard`) or compliance packs (`@aegis/soc2-guard`, `@aegis/hipaa-guard`) matching your threat model.

### ✅ 6. Verify Cryptographic Release Signatures
- **DO**: Verify package integrity via `npm audit signatures` or GitHub CLI attestations before deploying updates to production pipelines.

---

## 3. What NOT to DO (Anti-Patterns & Security Pitfalls)

### ❌ 1. DO NOT Bypass AST Parsing with Raw Regexes
- **DO NOT**: Rely on simple string contains checks (`query.includes("DROP")`) in place of AST parsing. Attackers routinely bypass regexes using SQL comment fragmentation (`DEL/**/ETE`), hex encodings, or unicode homoglyphs (`\u0430` for `a`), which Aegis normalizes and parses into concrete syntax trees.

### ❌ 2. DO NOT Disable Invariant Checks for "Trusted" Internal Agents
- **DO NOT**: Disable invariant verification for secondary or sub-agents in multi-agent workflows. In multi-agent architectures (e.g. LangGraph, CrewAI), secondary agents are prime targets for indirect prompt injection and privilege escalation.

### ❌ 3. DO NOT Expose the Gateway Control Plane to the Public Internet Without Mutual TLS
- **DO NOT**: Expose the Aegis Gateway HTTP service (`services/gateway`) without API key authentication, rate limiting, and TLS termination.

### ❌ 4. DO NOT Hardcode Production API Secrets in Rule Configurations
- **DO NOT**: Store plaintext API tokens or master cryptographic keys in `aegis.config.yaml` or Git repositories. Always pass sensitive credentials through environment variables or secure secret managers.

### ❌ 5. DO NOT Treat Compliance Dossiers as Formal CPA Certifications
- **DO NOT**: Present self-generated compliance dossiers (`generateComplianceDossier()`) as accredited third-party SOC 2 or HIPAA certifications. The dossier is a technical audit trail for human auditors.

---

## 4. Operational Checklist Before Going Live

| Check | Requirement | Verified |
| :--- | :--- | :---: |
| **Engine Mode** | Configured with `mode: 'enforce'` | [ ] |
| **Fail Policy** | Set to `failPolicy: 'fail-closed'` | [ ] |
| **Rule Packs** | Explicitly declared in config or constructor | [ ] |
| **DB Permissions** | Dedicated agent DB user with minimum required grants | [ ] |
| **Secret Scanning** | Zero hardcoded keys in repository | [ ] |
| **Package Provenance** | Verified via `npm audit signatures` | [ ] |

---

## 5. Security Incident Reporting

If you discover a security vulnerability or invariant bypass, report it confidentially under our [Security Policy](../SECURITY.md) via [GitHub Security Advisories](https://github.com/Snehgabani/aegis-kernel/security/advisories/new) or email `security@aegis-kernel.dev`.
