# Aegis Invariant Kernel: EU AI Act & GDPR Compliance Brief

**Target Audience:** European Union Compliance Officers, Data Protection Officers (DPOs), and Enterprise AI Architects.

---

## 1. Regulatory Context

The **European Union Artificial Intelligence Act (Regulation (EU) 2024/1689)** establishes strict regulatory obligations for providers and deployers of **High-Risk AI Systems** (Articles 6–15).

Aegis Invariant Kernel provides the technical control clearance layer necessary to fulfill EU AI Act requirements at the tool execution boundary.

---

## 2. EU AI Act Article-by-Article Mapping

| EU AI Act Article | Requirement | Aegis Invariant Enforcement |
| :--- | :--- | :--- |
| **Article 9** *(Risk Management System)* | Implementation of continuous, systematic identification and mitigation of operational AI risks. | In-process invariant gates intercept all tool mutations before execution and log every risk violation with SHA-256 tamper-evident proof hashes. |
| **Article 10** *(Data & Data Governance)* | Prevention of unintended biases, unauthorized processing of special category data, and data leakage. | Regex and AST checkers redact PII, National IDs, and Article 9 GDPR special categories (`@aegis/gdpr-guard`). |
| **Article 12** *(Record-Keeping & Logging)* | Automated recording of events ('logs') to ensure traceability of system operation throughout lifecycle. | 14-field JSON-Lines learning ledger records timestamp, tool name, sanitized parameters, fired rule IDs, and cryptographic hashes. |
| **Article 14** *(Human Oversight)* | Mechanism to enable human overseers to override, interrupt, or stop the system at any time. | Dual-key authorization requirement and immediate deterministic HALT upon invariant violation. |
| **Article 15** *(Accuracy, Robustness & Cybersecurity)* | Systems must be resilient against prompt injection, manipulation of inputs, and cyber threats. | AST SQL constant folding, zero-eval expression parsing, and runtime MCP schema pinning protect against malicious indirect injection. |

---

## 3. Deployment Guidance in the EEA

1. **Zero Data Export:** Aegis runs 100% in-process within European hosting regions (e.g., `eu-west-1`, `eu-central-1`). Zero agent tool data is exported to non-EEA countries.
2. **Deterministic Reproducibility:** Every security block generates a deterministic audit proof verifying that no subjective LLM bias influenced the clearance decision.
