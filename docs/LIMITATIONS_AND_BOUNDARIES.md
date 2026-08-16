# Aegis Invariant Kernel: Honest Technical Boundaries & Limitations

> **An Epistemically Rigorous Engineering Assessment of Deterministic vs. Probabilistic AI Security**  
> *Last Updated: August 2026*

---

## 🧭 Executive Summary: What Aegis Is and Is Not

In the AI security industry, vendors frequently overclaim that their products provide "100% complete agent security" or "eliminate all LLM vulnerabilities." This document provides an **intellectually honest, mathematically grounded, and unbiased breakdown** of what deterministic invariant checking solves, where its theoretical limits lie, and how it must be deployed in enterprise production architectures.

---

## 🎯 The Scope of Deterministic Clearance

Aegis is an **in-process, deterministic action-clearance kernel**. It operates strictly at the boundary where an AI agent attempts to execute an action (a function call, SQL query, financial transaction, file modification, or MCP tool execution).

```
                      ┌──────────────────────────────────────────────┐
                      │             AI AGENT WORKFLOW                │
                      │                                              │
                      │   [User Input] ──► [LLM Thinking / Chat]    │
                      │                           │                  │
                      │                     (Tool Call)              │
                      └───────────────────────────┼──────────────────┘
                                                  ▼
                                   ┌──────────────────────────────┐
                                   │  🛡️ AEGIS INVARIANT KERNEL   │
                                   │                              │
                                   │   • Multi-Dialect SQL AST    │
                                   │   • Numeric Range Ceilings   │
                                   │   • PII / Secrets / Regex    │
                                   │   • State Invariants         │
                                   └──────────────┬───────────────┘
                                                  │
                                 ┌────────────────┴────────────────┐
                                 ▼                                 ▼
                         [Allowed: <1.5ms]                 [Blocked: Feedback]
                                 │                                 │
                                 ▼                                 ▼
                     [(Database / API Server)]             [(Agent Self-Heal)]
```

---

## ⚖️ Honest Boundary Matrix: Deterministic vs. Probabilistic

| Threat Domain | Deterministic AST Clearance (Aegis) | Probabilistic LLM Guardrails (NeMo, Lakera, Guardrails AI) | Recommended Hybrid Best Practice |
| :--- | :--- | :--- | :--- |
| **SQL Injection / Mass Deletion (`WHERE 1=1`, CTEs, `DROP`)** | **Optimal**: 100% deterministic AST parsing in $<1.5$ms with zero bypass via comment evasion. | **Weak**: LLM judges can be hallucinated or jailbroken; high latency ($300-800$ms). | **Deploy Aegis at the DB tool boundary.** |
| **Financial Ceilings & Numeric Velocity** | **Optimal**: Strict mathematical comparisons ($<\$10,000$, velocity per hour) with zero drift. | **Poor**: LLMs struggle with precise arithmetic and numeric bounds. | **Deploy Aegis numeric invariants.** |
| **Secret Leaks (JWT, API keys, GCP SA keys, DB URIs)** | **Optimal**: Sub-millisecond pre-compiled regex + NFKD normalization. | **Moderate**: Slow; sending secrets to cloud APIs violates privacy boundaries. | **Deploy Aegis PII & secret masker in-process.** |
| **Conversational Tone / Politeness / Brand Voice** | ❌ **Out of Scope**: Deterministic engines do not evaluate subjective linguistic nuance. | **Strong**: LLM judges are well-suited for semantic tone and conversational style. | **Deploy LLM judge on conversational responses.** |
| **Multimodal Vision / Audio Hallucinations** | ❌ **Out of Scope**: Aegis only inspects structured tool arguments and schemas. | **Strong**: Vision-language models evaluate image/audio content. | **Deploy specialized vision guardrails.** |
| **Complex Social Engineering in Unstructured Chat** | ❌ **Out of Scope**: If an agent outputs text without calling tools, Aegis does not intercept. | **Moderate**: LLM classifiers evaluate intent in chat text. | **Deploy input/output conversational filters.** |

---

## 🔍 Known Failure Modes & Architectural Blind Spots

To eliminate confirmation bias, we explicitly document every known architectural limitation:

### 1. Non-Tool Conversational Deception
- **Limitation**: If a compromised agent convinces a human user to manually run a malicious command in their own terminal via plain-text chat, Aegis cannot intercept the user's manual action because no tool call was initiated through the agent runtime.
- **Remediation**: Use conversational input/output filters at the chat UI layer to complement Aegis at the action layer.

### 2. Proprietary / Exotic SQL Dialects
- **Limitation**: `SqlChecker` supports PostgreSQL, MySQL, SQLite, and TransactSQL. If an application uses an obscure proprietary SQL dialect with non-standard syntax, AST parsing may fall back to the token scanner.
- **Remediation**: Developers should test custom queries during `aegis init` and add custom regex/DSL rules if using non-standard database extensions.

### 3. Out-of-Band State Divergence
- **Limitation**: If an agent operates in a distributed cluster across multiple physical machines and relies on in-memory state without a shared Redis/database state provider, state invariant counters may diverge.
- **Remediation**: Use `AegisEngine.evaluateAsync()` with an asynchronous Redis/DB `StateProvider` hook to guarantee cross-node state consistency.

---

## 🔬 Benchmark Methodology & Academic Scope Disclosures

To ensure empirical validity and prevent Goodhart's Law:

1. **Academic Benchmark Scope**:
   - **Representative Sample Evaluation** (`packages/evals`): Runs a curated 27-vector representative sample of InjecAgent (13 vectors), AgentDojo (9 vectors), and MCP-Bench (5 vectors) in-process for sub-second, deterministic, zero-network-egress CI/CD validation.
   - **Full-Scale Evaluation**: For live multi-turn agent evaluations across thousands of scenarios with third-party LLMs, use the extensible CLI runner (`npx aegis eval all`) or the UK AISI Inspect AI solver adapter (`packages/evals/inspect/`).
   - **Adversarial Fuzz Corpus**: 433 generated vectors (300 malicious / 133 benign) synthesized via grammar fuzzing to stress-test AST edge cases.
2. **Transparent Latency Reporting**:
   - Latency figures represent end-to-end CPU time measured via `performance.now()` across 10,000 real iterations on commodity hardware, including P50 (0.318ms) and P95 (0.498ms) metrics.

---

## 💻 Language Implementation Maturity Tiers

| Language | Maturity Level | Scope & Status |
| :--- | :--- | :--- |
| **TypeScript / Node.js** | **Tier 1 (Production Engine)** | Complete multi-dialect SQL AST parser, JSON schema validator, Merkle audit chain, Gateway, CLI, and Live Studio. Ready for enterprise production workloads. |
| **Python (`>=3.9`)** | **Tier 2 (Production SDK)** | Zero-dependency in-process clearance, `@aegis_guard` decorator, and LangChain / CrewAI / AutoGen adapters. Ready for production Python agent pipelines. |
| **Go** | **Tier 3 (Reference Implementation)** | ~150 lines of protocol types and regex pattern checks. Minimal reference skeleton for protocol demonstration — not a full AST engine port. |
| **Rust** | **Tier 3 (Reference Implementation)** | Minimal zero-allocation scaffold and FFI bindings prototype. Experimental reference implementation. |

---

## 📜 Compliance Self-Assessment Disclaimer

- **Technical Evidence Only**: Aegis produces cryptographically signed Merkle audit dossiers and control evidence packets for SOC 2 Type II, ISO/IEC 42001:2023, EU AI Act, and NIST AI RMF 1.0.
- **Not a CPA Certification**: Aegis is an evidence-generating control enforcement tool. It is **NOT** a formal certification. Formal SOC 2 certification requires an independent audit by a licensed CPA firm, and PCI-DSS requires an assessment by a Qualified Security Assessor (QSA).

---

## 🛡️ Enterprise Recommendation: The Defense-in-Depth Model

Aegis is **not a replacement for foundational cybersecurity**. An enterprise AI deployment must implement all four layers:

1. **Layer 1: Identity & Authentication** — OAuth 2.0 / API key authentication per agent.
2. **Layer 2: Deterministic Action Clearance (Aegis)** — In-process AST and invariant verification before tool dispatch.
3. **Layer 3: Least Privilege Infrastructure** — Database read-only credentials, network segmentation, VPC endpoints.
4. **Layer 4: Continuous Audit & Telemetry** — Immutable event logging (`proofHash`) streamed to SIEM (Datadog, Splunk).
