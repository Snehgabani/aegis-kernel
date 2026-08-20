# Aegis Invariant Kernel: EU AI Act & GDPR Compliance Brief

**Target Audience:** European Union Compliance Officers, Data Protection Officers (DPOs), and Enterprise AI Architects.
**Legal status updated:** 2026-08-20 (post-Digital-Omnibus).

---

## 1. Regulatory Context — what is in force *today*

The **EU AI Act (Regulation (EU) 2024/1689)** is amended by the **Digital Omnibus
(Regulation (EU) 2026/1744**, in force 2026-07-27). The practical picture for
agent platform teams as of **August 2026**:

| Obligation | Status | Date |
| :--- | :--- | :--- |
| **Article 50 transparency** (AI-interaction disclosure, synthetic-content marking, deepfake labelling) | **IN FORCE — enforceable** | **2026-08-02** |
| Machine-readable marking for generative systems **already on the market** before 2026-08-02 | Grace period | until 2026-12-02 |
| **GPAI provider obligations** (transparency, copyright, systemic-risk duties) | In force; Commission fining power (Art. 101) active from 2026-08-02 | 2025-08-02 / 2026-08-02 |
| **Article 4 AI literacy** (deployers ensure staff AI literacy) | In force (softened wording by Omnibus) | 2025-02-02 |
| **Annex III high-risk obligations** (Articles 8–15: risk mgmt, logging, oversight, accuracy) | **Deferred by Omnibus** | **2027-12-02** |
| Annex I embedded high-risk (products legislation) | Deferred | 2028-08-02 |

Enforcement: national market-surveillance authorities can act on Article 50
breaches from 2026-08-02; fines up to **€15M or 3% of worldwide turnover**.

**What this means for buyers:** the *live* August-2026 obligation set is
**Article 50 transparency + GPAI duties + AI literacy** — evidence-heavy
obligations that Aegis supports today (below). The Article 9–15 high-risk
package is the **December 2027** story: organizations should use the runway to
build the logging and oversight evidence Aegis automates, not wait.

Aegis Invariant Kernel provides the technical control and **evidence layer** at
the tool execution boundary for both horizons.

---

## 2. Live obligations (since 2026-08-02) — Aegis support

| Obligation | Requirement | Aegis Invariant Enforcement / Evidence |
| :--- | :--- | :--- |
| **Article 50(1)** *(Disclosure of AI interaction)* | Deployers must ensure users are informed they are interacting with an AI system | Every agent-initiated tool call passes through Aegis and produces a signed `AegisEvent` ledger record (framework, tool, verdict, proof hash) — a tamper-evident, per-interaction evidence trail that an AI system was in the loop, exposable in audit and disclosure workflows. |
| **Article 50(2)** *(Machine-readable marking of synthetic output)* | Providers of generative systems mark outputs in machine-readable form | Aegis proof hashes (`proofHash`, Merkle-chained) and verdict metadata can be attached to agent-generated artifacts to carry provenance/marking metadata through the tool chain (marking UI remains the deployer's application responsibility). |
| **Article 50(3)/(4)** *(Deepfake & emotion-recognition labelling)* | Label synthetic/manipulated content | Ledger records classify the producing tool call, supporting labelling pipelines with verifiable provenance. |
| **GPAI transparency** *(technical documentation, copyright policy)* | GPAI providers publish training-data summaries & policies | Out of Aegis's scope (model-provider duty). Aegis covers the *deployer-side* evidence: which tools agents called, what was blocked, and why — deterministically. |
| **Article 4 AI literacy** | Deployers ensure staff AI literacy | Aegis `GET /health/deep` engine self-tests, explainability payloads (`suggestedFix`, `explainability` traces) and this documentation reduce the operational-knowledge burden for oversight staff. |

## 3. High-risk package (Articles 9–15, applicable 2027-12-02) — Aegis mapping

Aegis automates the evidence these articles require; adopting early converts the
2027 deadline from a project into a report.

| EU AI Act Article | Requirement | Aegis Invariant Enforcement |
| :--- | :--- | :--- |
| **Article 9** *(Risk Management System)* | Continuous, systematic identification and mitigation of operational AI risks. | In-process invariant gates intercept all tool mutations before execution and log every risk violation with SHA-256 tamper-evident proof hashes. |
| **Article 10** *(Data & Data Governance)* | Prevention of unintended biases, unauthorized processing of special category data, and data leakage. | Regex and AST checkers redact PII, National IDs, and Article 9 GDPR special categories (`@aegis/gdpr-guard`). |
| **Article 12** *(Record-Keeping & Logging)* | Automated recording of events ('logs') to ensure traceability of system operation throughout lifecycle. | 14-field JSON-Lines learning ledger records timestamp, tool name, sanitized parameters, fired rule IDs, and cryptographic hashes — automatically kept ≥ 6 months in enforce deployments. |
| **Article 13** *(Transparency & Instructions for Use)* | Instructions allowing deployers to interpret output and use the system properly. | Every verdict ships a deterministic explanation (`violations[]`, `suggestedFix`, diagnostic traces) suitable for inclusion in deployer instructions. |
| **Article 14** *(Human Oversight)* | Mechanism to enable human overseers to override, interrupt, or stop the system at any time. | Dual-key authorization requirement and immediate deterministic HALT upon invariant violation; HITL approval gates for sensitive tools. |
| **Article 15** *(Accuracy, Robustness & Cybersecurity)* | Systems must be resilient against prompt injection, manipulation of inputs, and cyber threats. | AST SQL constant folding, zero-eval expression parsing, and runtime MCP schema pinning protect against malicious indirect injection — deterministically, with zero egress. |

## 4. Complementary frameworks Aegis evidence supports today

- **ISO/IEC 42001:2023** (AI management systems): Aegis ledger + GRC dossiers
  provide the control-operation records internal audits require.
- **NIST AI RMF**: MAP/MEASURE/MANAGE functions map to Aegis rulepack inventory,
  per-verdict metrics (incl. OTel GenAI spans), and policy commitment hashes.

## 5. Deployment Guidance in the EEA

1. **Zero Data Export:** Aegis runs 100% in-process within European hosting regions (e.g., `eu-west-1`, `eu-central-1`). Zero agent tool data is exported to non-EEA countries. Cloud telemetry and webhooks are strictly opt-in and clearly separated from the hot path.
2. **Deterministic Reproducibility:** Every security block generates a deterministic audit proof verifying that no subjective LLM bias influenced the clearance decision.
3. **2026 actions (Art. 50 era):** enable ledger retention, wire the OTel GenAI
   spans into your SIEM, and use GRC dossier exports as Article 50 / AI-literacy
   evidence. **2027 actions (high-risk era):** the Article 9–15 mapping above.

---

*This document is engineering guidance, not legal advice; confirm obligations
with counsel for your specific risk classification.*
