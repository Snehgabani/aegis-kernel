# 🔒 Security Controls & GRC Compliance Dossiers

Aegis Invariant Kernel automatically compiles cryptographically verifiable Governance, Risk, and Compliance (GRC) audit evidence dossiers during runtime execution.

---

## 📋 Regulatory Alignment Matrix

| Regulation / Framework | Control Requirement | Aegis Invariant Enforcement |
| :--- | :--- | :--- |
| **SOC2 Type II** | CC6.1, CC6.6 (Logical Access & Boundary Protection) | Ed25519 Biscuit token delegation & RBAC clearance |
| **HIPAA Security Rule** | §164.312(a)(2)(iv) (Encryption & Tokenization) | In-process PII Token Vault with per-session cryptographic salt |
| **EU AI Act** | Article 14 (Human Oversight & Tool Firewalls) | Human-in-the-loop (HITL) cryptographic approval workflows |
| **NIST AI RMF** | GOVERN 1.2, MAP 2.3, MANAGE 3.1 | Deterministic AST invariants & zero-egress audit trails |
| **OWASP LLM Top 10** | LLM01 (Prompt Injection), LLM02 (Sensitive Info) | Linear prompt classifier, MCP schema poisoning scanner |

---

## 🔗 SHA-256 Merkle Audit Chain

Every tool clearance decision records an event in an append-only cryptographic chain:
- Each block hashes the current event payload + the previous block's root hash.
- Generates tamper-evident cryptographic proofs (`verifyChainIntegrity()`).
- Exports compliant JSON evidence packages for external SIEMs (Splunk, Datadog, AWS CloudWatch).
