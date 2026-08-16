# 🛡️ Aegis Invariant Kernel: Architectural Boundaries, Disclosures & Defense-in-Depth

This document defines the formal operational boundaries, threat model scope, benchmark ingestion methodology, and multi-language engine architectures of **Aegis Invariant Kernel**.

---

## 🎯 Architectural Scope & The Hybrid Guardrail Model

Aegis is purpose-built as a **Deterministic Invariant Gateway for Tool Calls & State Mutations**. It is designed to operate seamlessly alongside conversational LLM moderation frameworks in a **2-stage defense-in-depth pipeline**:

```
[ User Input ]
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ STAGE 1: Conversational / Tone Moderation (LLM Judge)       │
│ • Natural language toxicity, hate speech, brand tone        │
│ • Handled by Llama Guard, NeMo Guardrails, or LLM-as-Judge  │
└──────────────────────────────┬──────────────────────────────┘
                               │ (Clean Prompt Passed)
                               ▼
                        [ LLM Agent ]
                               │ (Proposes Tool Action)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ STAGE 2: Aegis Deterministic Invariant Clearance (<1.5ms)   │
│ • Multi-dialect SQL AST mutations (DROP, TRUNCATE, DELETE)  │
│ • Deep tautology constant-folding (WHERE 1, id>0, 2>1)      │
│ • Exact numeric ceilings & currency aliasing (total, price) │
│ • Salted PII/Secret token vaults & zero-egress data bounds  │
│ • State invariants & multi-tenant isolation                 │
│ • Cryptographically signed Merkle audit ledger (Ed25519)    │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       [ BLOCKED (<1ms) ]              [ ALLOWED (<1ms) ]
   Deterministic Self-Healing         Execute Tool Action
```

| Operational Domain | In Scope (Aegis Invariant Kernel) | Out of Scope (Deploy Complementary Layer) | Recommended Tooling |
| :--- | :--- | :--- | :--- |
| **SQL Injections & Mass Data Loss** | **AST & Token Analysis (<1.5ms)** | Conversational SQL prompt rewriting | Aegis at Database Boundary |
| **Financial Overspends & Numeric Ceilings** | **Exact Arithmetic & Alias Bounds (<0.2ms)** | Subjective negotiation coaching | Aegis Numeric Invariants |
| **Secrets & PII Exfiltration** | **In-Process Salted Masking (<0.3ms)** | Sentiment analysis & tone policing | Aegis In-Process Vault |
| **Conversational Tone / Politeness** | ❌ Out of scope by design | **Natural Language Nuance & Tone** | Llama Guard / NeMo Guardrails |
| **Multimodal Vision / Audio Streams** | ❌ Out of scope by design | **Multimodal Harm Detection** | Vision / Audio Moderation Models |

---

## 💻 Native Multi-Language Engine Architectures

Aegis provides native, zero-network-egress invariant verification engines across four primary languages:

| Language | Engine Architecture | Invariant Capabilities | Test Suite Status |
| :--- | :--- | :--- | :--- |
| **TypeScript / Node.js** | **Native Core Engine** | Multi-dialect AST parsing, JSON schema compilation, Merkle audit chain, Gateway, CLI, Live Studio | **509/509 tests (67 suites)** |
| **Python (`>=3.9`)** | **Native Zero-Dep Engine** | Multi-dialect SQL token parsing, financial aliases, PII salted token vault, State DSL, CrewAI/AutoGen/LangChain adapters | **11/11 tests (100% Green)** |
| **Go (`>=1.21`)** | **Native Go Engine (`packages/go`)** | Multi-dialect SQL token & AST validator, comment de-obfuscation, tautology engine, currency parser, salted PII vault, State DSL, `Guard` wrapper | **17/17 tests (100% Green)** |
| **Rust (`>=1.75`)** | **Native Rust Crate (`packages/rust`)** | Zero-allocation SQL AST/token invariant validator, tautology constant-folding, financial aliases, salted HMAC token vault, ZK policy circuits & Nitro attestation | **8/8 integration tests (100% Green)** |

---

## 🔬 Standardized Academic Benchmark Ingestion & CLI Adapters

Aegis provides standardized, reproducible dataset ingestion adapters and evaluation commands for major academic agent security benchmarks:

### 1. Supported Benchmark Adapters
- **InjecAgent (ACL 2024 / EMNLP 2024)**: Ingests canonical JSON/JSONL test vectors across Direct Harm (DH) and Data Exfiltration (DE) threat models.
- **AgentDojo (NeurIPS 2024)**: Ingests multi-domain task suites across Banking, Workspace, Slack, and Travel domains.
- **MCPTox / MCP-Bench**: Evaluates Model Context Protocol tool definitions for zero-width Unicode characters, homoglyphs, and embedded injection payloads.

### 2. Execution Commands
```bash
# Evaluate InjecAgent academic benchmark suite
aegis eval injecagent --output ./injecagent-report.json

# Evaluate AgentDojo multi-domain security benchmark suite
aegis eval agentdojo --output ./agentdojo-report.json

# Evaluate MCP tool poisoning security suite
aegis eval mcptox --output ./mcptox-report.json

# Run all academic benchmark suites with aggregated cryptographic attestation
aegis eval all --output ./academic-evidence.json
```

All reports output exact statistical percentiles (Mean, Min, Max, P50, P95, P99), precision, recall, empirical F1 score, and a **SHA-256 Cryptographic Attestation Proof**.

---

## 📜 CPA / Auditor Verification Workflow & Legal Disclaimers

### 1. Cryptographic Evidence Dossiers
Aegis generates structured, tamper-evident GRC compliance dossiers with:
- SHA-256 Merkle root hash chains binding every tool clearance decision.
- Asymmetric **Ed25519 digital signatures** or symmetric **HMAC-SHA256 signatures**.
- 18-control crosswalks mapped to **SOC 2 Type II** (CC6.1, CC6.6, CC6.8, PI1.1, PI1.2), **ISO/IEC 42001:2023** (Annex A.6.2.7, A.8.2/8.4, A.9.2/9.3), **HIPAA Security Rule** (§164.312(a)(1), (b), (c)(1), (e)(1)), **NIST AI RMF 1.0**, and **EU AI Act**.
- AICPA SSAE 18 attestation blocks for CPA audit workpapers.

### 2. Proof Verification CLI
Auditors and security teams can independently verify dossier integrity without running the engine:
```bash
# Verify compliance dossier with public key or symmetric secret
aegis verify-proof compliance-dossier.json --key "corp-signing-secret"
```

### 3. Compliance Disclaimer
> [!IMPORTANT]
> **Technical Evidence Only**: Aegis produces cryptographically verifiable evidence and enforces technical invariants. It is **NOT** a formal certification. Formal SOC 2 certification requires an independent audit by a licensed CPA firm, and ISO 42001 certification requires an assessment by an accredited certification body. Aegis provides the automated technical evidence generation engine that enables auditors to complete those assessments with cryptographic certainty.
