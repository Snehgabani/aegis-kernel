# 🛡️ Aegis Invariant Kernel — OWASP GenAI Top 10 (2026) & MITRE ATLAS Cross-Walk

A comprehensive compliance and threat mitigation cross-walk mapping the **OWASP GenAI Top 10 (2026)** and **MITRE ATLAS (Adversarial Threat Landscape for AI Systems)** matrices to Aegis Invariant Kernel enforcement checkers.

---

## 🗺️ Unified Security Cross-Walk Matrix

| OWASP 2026 Category | MITRE ATLAS Technique ID | Adversarial Threat Vector | Aegis Invariant Checker & Pack | Enforcement Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **LLM01: Prompt Injection & Jailbreak** | `AML.T0051` / `AML.T0054` | Indirect prompt injection hijacking tool arguments into destructive database queries or payouts | **`SqlChecker`**<br>**`@aegis/sql-guard`** | AST statement type whitelist, block-comment evasion detection, tautology stripping |
| **LLM02: Sensitive Information Disclosure** | `AML.T0048` / `AML.T0053` | Exfiltration of API tokens, OpenAI keys, AWS secret tokens, SSNs, credit cards via tool arguments | **`PiiChecker`**<br>**`@aegis/data-guard`** | Zero-width unicode normalization (`\u200B`, `\uFEFF`), entropy scanning, token redaction |
| **LLM06: Excessive Agency & Tool Abuse** | `AML.T0056` | Autonomous agent making unauthorized multi-thousand dollar payouts or rogue API calls | **`NumericChecker`**<br>**`@aegis/finance-guard`** | Hard mathematical currency caps, scientific notation parsing (`1e6`), sliding-window velocity caps |
| **LLM07: System Prompt & Cross-Tenant Leakage** | `AML.T0057` | Agent bypassing tenant boundaries or accessing unauthorized customer records across partitions | **`StateChecker`**<br>**`@aegis/soc2-guard`** | Session tenant hash verification (`state.tenantId == params.tenantId`), strict boundary lock |
| **LLM08: Vector & State Memory Tampering** | `AML.T0058` | Malicious manipulation of agent context state or corrupting long-term memory | **`Ledger`**<br>**`AegisEngine`** | Cryptographic SHA-256 state commitment (`proofHash`), tamper-evident FIFO ledger |
| **LLM10: Unbounded Consumption & DoS** | `AML.T0029` | Computational exhaustion through millions of recursive tool calls or CPU-heavy payload queries | **`SqlChecker`**<br>**`CustomChecker`** | Enforces mandatory `LIMIT` clause on all `SELECT` queries; payload depth recursion limits |

---

## 🏛️ Verification & Audit Command

Enterprise security teams can verify active cross-walk protections directly in the terminal:

```bash
# Display live threat coverage across all 8 active packs
npx aegis matrix
```
