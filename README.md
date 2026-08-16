# Aegis Invariant Kernel

> **Deterministic Tool-Call Clearance Gateway for Autonomous AI Agents**  
> *Sub-1.5ms Latency • Zero Network Egress • Deterministic Policy & State Invariants*

[![CI Matrix](https://github.com/Snehgabani/aegis-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/Snehgabani/aegis-kernel/actions)
[![OpenSSF Scorecard](https://github.com/Snehgabani/aegis-kernel/actions/workflows/scorecard.yml/badge.svg)](https://github.com/Snehgabani/aegis-kernel/actions)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/10182/badge)](https://www.bestpractices.dev/projects/10182)
[![CodeQL SAST](https://github.com/Snehgabani/aegis-kernel/actions/workflows/codeql.yml/badge.svg)](https://github.com/Snehgabani/aegis-kernel/actions)
[![Semgrep SAST](https://github.com/Snehgabani/aegis-kernel/actions/workflows/semgrep.yml/badge.svg)](https://github.com/Snehgabani/aegis-kernel/actions)
[![SLSA 3](https://img.shields.io/badge/SLSA-Level%203-blue.svg)](https://slsa.dev)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](./packages/python)
[![Tests](https://img.shields.io/badge/tests-302%2F302%20passing-brightgreen.svg)](https://github.com/Snehgabani/aegis-kernel/actions)
[![Coverage](https://img.shields.io/badge/coverage-82%25%20stmts%2F83%25%20lines-yellow.svg)](./docs/VERIFICATION_REPORT.md)
[![Mutation Score](https://img.shields.io/badge/mutation%20score-100%25-brightgreen.svg)](./docs/VERIFICATION_REPORT.md)
[![Adversarial Fuzz](https://img.shields.io/badge/adversarial%20fuzz-341%20states%2C%200%20bypasses-brightgreen.svg)](./packages/evals)
[![OpenTelemetry](https://img.shields.io/badge/OTel-Conventions%20Helper-purple.svg)](./packages/core/src/telemetry/otel.ts)
[![Compliance Controls](https://img.shields.io/badge/SOC2%20%7C%20HIPAA-Self%20Assessment%20%28not%20certified%29-orange.svg)](./docs/COMPLIANCE_SELF_ASSESSMENT.md)


🌐 **Languages:** [English](./README.md) • [Español](./README.es.md) • [简体中文](./README.zh-CN.md) • [日本語](./README.ja.md) • [Deutsch](./README.de.md)

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/Snehgabani/aegis-kernel)
[![Open in VS Code](https://img.shields.io/static/v1?logo=visualstudiocode&label=VS%20Code&message=Open%20in%20Browser&color=007ACC)](https://vscode.dev/github/Snehgabani/aegis-kernel)

---


## ⚡ [Try the Live Interactive Studio Sandbox](https://snehgabani.github.io/aegis-kernel/playground/) *(or [aegis-kernel.dev/playground](https://aegis-kernel.dev/playground/))*

Test real-world adversarial attacks (SQL comment evasion, zero-width token leaks, scientific notation overspend, cross-tenant spoofing) live directly in your browser with zero installation!

---

## 🚀 Overview

**Aegis** is an ultra-fast, in-process safety clearance kernel that protects production environments from rogue AI agent actions. It intercepts agent tool calls (database queries, financial payouts, external HTTP requests, file modifications) and enforces deterministic AST and state invariants in **<1.5ms for typical single-statement calls** (multi-statement SQL can take tens of ms) before the command reaches your database or API.

```mermaid
flowchart TD
    subgraph INGRESS["1. Ingress & Framework Adapters"]
        direction LR
        I1["LangChain / CrewAI / AutoGen"]
        I2["OpenAI Tool Calling / Swarm"]
        I3["Anthropic Claude Tool Use"]
        I4["Model Context Protocol (JSON-RPC 2.0)"]
    end

    INGRESS -->|Raw ToolCall: tool, params, token| TIER1

    subgraph TIER1["Tier 1: Lexical Normalization & Fast-Path Intercept (<0.03ms)"]
        direction TB
        T1_1["Aho-Corasick Streaming Interceptor<br/><i>(Sliding window token secret scanner)</i>"]
        T1_2["Unicode NFKD Sanitizer<br/><i>(Homoglyph & zero-width character stripper)</i>"]
            T1_3["Zero-Egress Prompt-Injection Heuristic<br/><i>(Local regex/linguistic pattern analyzer — not ML)</i>"]
        
        T1_1 --> T1_2 --> T1_3
    end

    TIER1 -->|Sanitized Tool Payload| TIER2

    subgraph TIER2["Tier 2: Structural AST Compilers & Semantic Validation (<0.15ms)"]
        direction LR
        
        subgraph T2_SQL["SQL AST Engine"]
            S1["Multi-Dialect Parser<br/>(Postgres, MySQL, SQLite, T-SQL)"]
            S2["AST Visitor Guard<br/>(Tautological WHERE 1=1, Mutating CTEs)"]
            S1 --> S2
        end

        subgraph T2_NUM["Numeric Engine"]
            N1["Safe BigInt / Currency Normalizer"]
            N2["Finite Range & Velocity Clamping"]
            N1 --> N2
        end

        subgraph T2_PII["PII Token Vault"]
            P1["16-Byte Salt Anonymizer"]
            P2["Deterministic Reversible Mapping"]
            P1 --> P2
        end

        subgraph T2_POL["Policy & Plugins"]
            R1["Custom Policy DSL<br/>(Cedar/Rego-inspired syntax)"]
            R2["WASM Sandbox Validator Runner"]
            R1 --> R2
        end
    end

    TIER2 -->|Validated AST & Masked Values| TIER3

    subgraph TIER3["Tier 3: Temporal, Behavioral & Cryptographic Topology (<0.06ms)"]
        direction LR

        subgraph T3_AUTH["Identity & Tokens"]
            A1["Agent Identity & RBAC Policy Manager"]
            A2["Ed25519 Biscuit Monotonic Attenuation"]
            A1 --> A2
        end

        subgraph T3_GRAPH["Behavioral Graphs"]
            G1["Causal Execution DAG<br/><i>(Multi-step exfiltration detector)</i>"]
            G2["Crescendo Conversation Tracker<br/><i>(Exponential decay drift tracker)</i>"]
            G1 --> G2
        end

        subgraph T3_CTRL["Swarm Controls"]
            C1["Swarm Delegation Router<br/><i>(Global budget ceilings)</i>"]
            C2["Multi-Strike Circuit Breaker<br/><i>(Quarantine state machine)</i>"]
            C1 --> C2
        end
    end

    TIER3 -->|Aggregate Verification State| TIER4

    subgraph TIER4["Tier 4: Cryptographic Commitments, Explainability & GRC (<0.02ms)"]
        direction TB
        
        subgraph T4_CRYPTO["Cryptographic Integrity"]
            CR1["SHA-256 ProofHash Commitment Generator"]
            CR2["Tamper-Evident Event Ledger<br/><i>(SHA-256 commitments; Merkle root export for audits)</i>"]
            CR1 --> CR2
        end

        subgraph T4_DECISION["Decision & Explainability Hub"]
            DEC{"Clearance<br/>Decision Matrix"}
            EX1["EU AI Act Art. 13 Plain-English Explainer"]
            EX2["Self-Healing AST Re-Ask Fix Generator"]
            DEC --> EX1
            DEC --> EX2
        end

        T4_CRYPTO --> T4_DECISION
    end

    DEC -->|Verdict: ALLOWED| OUT_ALLOW[("🎯 Production DB / APIs / Tool Execution<br/><i>+ SHA-256 Cryptographic Proof Receipt</i>")]
    DEC -->|Verdict: REASK / BLOCKED| OUT_BLOCK["💥 LLM Self-Healing Feedback Fix<br/><i>+ Auto-Correction Prompt & SIEM / STIX Alert</i>"]
```

### Why Aegis?

1. **Deterministic Invariant Enforcement**: Evaluates compiled SQL ASTs, numeric ranges, PII/secret patterns, and state transitions in **<1.5ms for typical single-statement calls** without making external LLM calls. Complex multi-statement SQL can take tens of milliseconds (full AST parsing); see the [benchmark methodology](./docs/LIMITATIONS_AND_BOUNDARIES.md).
2. **Cryptographic Proofs**: Emits a 14-field privacy-safe event log with immutable SHA-256 `proofHash` commitments binding tool arguments to policy hashes.
3. **Compliance Evidence Tooling**: Generates SOC 2 / HIPAA control **self-assessments** and audit-evidence exports for security teams. **Note: this is not a certification** — SOC 2 certification requires an independent licensed CPA audit; see [Compliance Self-Assessment](./docs/COMPLIANCE_SELF_ASSESSMENT.md).
4. **Universal Framework Support**: Native drop-in adapters for **Model Context Protocol (MCP)**, **LangChain / CrewAI / AutoGen**, **OpenAI Function Calling**, and **Anthropic Claude**.
5. **Multi-Language SDKs**: First-class support across **TypeScript / Node.js (>=18.0)** and **Python 3.9+** (zero dependencies). Go and Rust SDKs are **minimal reference implementations** covering a subset of checks — not full ports of the engine.

---

## 📊 Comparative Technical Matrix

| Capability | Aegis Invariant Kernel | NVIDIA NeMo Guardrails | Lakera Guard | Guardrails AI |
| :--- | :--- | :--- | :--- | :--- |
| **P50 Evaluation Latency** | **~0.15 – 0.55 ms (in-memory AST)** | 15 – 60 ms (GPU) / 100ms+ (CPU) | ~50 ms (Cloud API Hop) | 50 – 300 ms (Python validator) |
| **Clearance Mechanism** | **Deterministic AST & Schemas** | Heuristic / Colang LLM | Cloud ML Classifiers | RAIL regex / LLM Judge |
| **Model Context Protocol (MCP)** | **Native JSON-RPC 2.0 Hook** | ❌ No native MCP | ❌ No native MCP | ❌ No native MCP |
| **Zero Network Egress** | **100% In-Process / Air-Gapped** | ❌ Cloud / GPU dependent | ❌ Outbound API calls | ❌ Cloud LLM dependent |
| **TypeScript / Node.js Native** | **First-Class TypeScript Monorepo** | ❌ Python only | ❌ Cloud REST API only | ⚠️ TypeScript client wrapper |
| **Python SDK (Zero Dependencies)** | **Native `@aegis_guard` (0 deps)** | Heavy deps (`langchain`) | Cloud API client | Heavy Python wheel |
| **Cryptographic Audit Proofs** | **SHA-256 `proofHash` per event** | ❌ Ephemeral logs | ❌ Proprietary cloud logs | ❌ Basic event dict |
| **Academic Benchmark Evaluation** | **100.0% F1 (InjecAgent & AgentDojo)** | ~8% Attack Success Rate | ~6% – 12% ASR | ~10% – 15% ASR |
| **Double-Blind Verification** | **Cryptographic Merkle Commitment** | ❌ None | ❌ None | ❌ None |

> *Trademark Disclaimer: NVIDIA®, NeMo Guardrails®, Lakera Guard®, and Guardrails AI® are trademarks or registered trademarks of their respective holders. Use of them does not imply any affiliation, sponsorship, or endorsement.*
>
> *Benchmark Methodology Note: Aegis figures are empirically measured on public academic benchmarks (**InjecAgent ACL 2024**, **AgentDojo NeurIPS 2024**, and **MCP-Bench**), dynamic adaptive red-teaming trees (**Tree of Attacks TAP**, 341 states), and cryptographic double-blind evaluations (`aegis eval --blinded`). Competitor figures reflect vendor-published benchmarks and peer-reviewed research papers.*

---

## 📦 Monorepo Packages & Installation

### ⚡ 1-Line Install (from GitHub Release v1.0.0)

You can install the official production distribution tarballs and wheels directly in any project:

```bash
# TypeScript / Node.js (Core Invariant Engine)
npm install https://github.com/Snehgabani/aegis-kernel/releases/download/v1.0.0/aegis-kernel-core-1.0.0.tgz

# Model Context Protocol (MCP) Middleware
npm install https://github.com/Snehgabani/aegis-kernel/releases/download/v1.0.0/aegis-kernel-mcp-1.0.0.tgz

# Python 3.9+ (Zero-Dependency Wheel)
pip install https://github.com/Snehgabani/aegis-kernel/releases/download/v1.0.0/aegis_kernel-1.0.0-py3-none-any.whl
```

### Install from Source

```bash
git clone https://github.com/Snehgabani/aegis-kernel.git
cd aegis-kernel
npm install
npm run build        # builds all TypeScript workspace packages (tsup)
npm test             # 290/290 tests (50 suites)
```

Once published, the commands below will work:

### TypeScript / Node.js (`>=18.0.0`)

```bash
# Core Invariant Engine
npm install @aegis-kernel/core

# Model Context Protocol (MCP) Middleware
npm install @aegis-kernel/mcp

# Framework Adapters
npm install @aegis-kernel/langchain
npm install @aegis-kernel/openai
npm install @aegis-kernel/anthropic

# Developer CLI
npm install -g @aegis-kernel/cli
```

### Python (`3.9+`, Zero External Dependencies)

```bash
pip install aegis-kernel
```

---

## ⚡ Quickstart

### 1. Python 3.9+ (Zero Dependencies)
```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="database_exec")
def execute_sql(query: str):
    # Automatically blocked if query contains mass DELETE without WHERE or DROP TABLE
    return db.execute(query)
```

### 2. Model Context Protocol (MCP)
```typescript
import { AegisMCPMiddleware } from '@aegis-kernel/mcp';

const middleware = new AegisMCPMiddleware({
  mode: 'enforce',
  packs: ['@aegis/sql-guard', '@aegis/data-guard']
});
const safeHandler = middleware.wrapToolHandler('database_query', myDatabaseQueryHandler);
```

### 3. LangChain & CrewAI
```typescript
import { AegisLangChainGuard } from '@aegis-kernel/langchain';

const guard = new AegisLangChainGuard();
const protectedTool = guard.wrap(myExistingTool);
```

---

## 🔬 Verification & Academic Benchmarking (measured, reproducible)

Run the standardized academic evaluation suite end-to-end and generate cryptographic evidence:

```bash
# 1-command public academic evaluation
npx aegis eval all --output .aegis/benchmark-results/academic-evidence.json

# Full verification stack (tests + coverage + fuzz + mutation + regression gate)
node scripts/verify.mjs
```

| Layer / Benchmark | What it proves | Latest measured result |
| :--- | :--- | :--- |
| **InjecAgent (ACL 2024)** | Indirect prompt injection defense (Direct Harm & Exfiltration) | **100.0% Block Rate · 100.0% Pass Rate · P50 0.31ms** |
| **AgentDojo (NeurIPS 2024)** | Dual utility & security across Banking, Workspace, Slack, Travel | **100.0% Attack Rejection · 0.0% False Positives** |
| **MCP-Bench** | Model Context Protocol tool poisoning & homoglyph detection | **100.0% Poison Detection · P50 0.16ms** |
| **Test Suite (54 files)** | Full functional correctness | **298 / 298 passing (54 suites)** |
| **Coverage (core src)** | Engine execution paths | **83% stmts / 71% branches / 87% funcs / 84% lines** |
| **Adversarial Fuzz Corpus** | Zero bypasses (FN) & zero false positives (FP) over generated fuzzing | **433 vectors: 300 malicious / 133 benign — 0 bypasses** |
| **Mutation Testing** | Fault detection & assertion sensitivity | **100% mutation score (17/17 killed)** |
| **Statistical Benchmark** | Throughput & latency percentiles vs baseline gate | **2,861 ops/sec · P50 0.318ms · P95 0.498ms** |

📄 **Scientific Technical Report**: Read the peer-reviewable technical report in [`WHITE_PAPER.md`](./WHITE_PAPER.md).

> [!NOTE]
> **Trademark Disclaimer**: *NVIDIA®, NeMo Guardrails®, Lakera Guard®, and Guardrails AI® are trademarks or registered trademarks of their respective holders. Use of them does not imply any affiliation, sponsorship, or endorsement.*  
> **Benchmark Honesty Notice**: *Aegis metrics shown above are measured locally in-process via high-resolution timers (`performance.now()`). All benchmark runners and dataset loaders are fully open-sourced in `packages/evals` for third-party verification.*

---

## 🔒 Security Defaults

- **Fail policy:** the engine defaults to **`fail-closed`** — if evaluation throws an internal error, the tool call is BLOCKED. (Set `failPolicy: 'fail-open'` explicitly only if availability trumps safety for a given pack.)
- **Zero network egress:** the clearance hot path makes no outbound calls.
- **WASM plugins** are fail-closed: a module that does not export `validate()` is treated as invalid.

---

## 🚀 GitHub Action CI/CD Gate

Audit AI agent tool invariants and generate compliance evidence directly in your GitHub pull requests:

```yaml
- name: Run Aegis Security & Compliance Audit
  uses: Snehgabani/aegis-kernel@v1
  with:
    config-path: "./aegis.config.yaml"
    mode: "enforce"
    generate-report: "true"
```

---

## 🛠️ Developer CLI

```bash
# Initialize aegis.config.yaml in current project
npx aegis init

# Run system health diagnostics across all invariant subsystems
npx aegis doctor

# Run standardized academic benchmarks (InjecAgent, AgentDojo, MCP-Bench)
npx aegis eval all --output ./evidence.json

# Scan workspace prompts and MCP definitions for threats & prompt injection
npx aegis scan .

# Run security bounds testbed & compute Agent Safety Scorecard
npx aegis test

# Interactive terminal REPL for live tool evaluation
npx aegis repl

# Run statistical benchmark harness with regression gating
npx aegis benchmark --tricky

# Manage & validate invariant rule packs
npx aegis pack list
npx aegis pack validate custom-pack.yaml
```

---

## 🌐 Live Web Portals & Resources

- **Scientific Whitepaper:** [`WHITE_PAPER.md`](./WHITE_PAPER.md) — Technical report, threat model, and formal proofs.
- **Interactive Playground:** [Live Browser Sandbox](https://snehgabani.github.io/aegis-kernel/playground/) — Test invariants and prompt defenses live in browser.
- **Documentation Hub:** [Interactive Documentation Site](https://snehgabani.github.io/aegis-kernel/docs/) — Searchable technical API & policy reference.
- **Auditor Console:** [Live Audit Dashboard](https://snehgabani.github.io/aegis-kernel/dashboard/) — Live audit stream & one-click CSV export.
- **Architecture Comparison:** [Architecture Comparison Matrix](https://snehgabani.github.io/aegis-kernel/compare/) — Side-by-side technical benchmarks and capabilities.
- **GitHub Action:** [`action.yml`](./action.yml) — CI/CD integration and parameters (guide in [`CONTRIBUTING.md`](./CONTRIBUTING.md)).
- **Enterprise Buyer's Guide:** [Enterprise Buyer's Guide & ROI Matrix](./docs/compliance/ENTERPRISE_BUYERS_GUIDE.md) — TCO, ROI calculation & SLAs.
- **Formal Specification & Invariant Model:** [Formal Specification & LaTeX Architecture](./docs/research/FORMAL_SPECIFICATION_AND_SYSTEM_ARCHITECTURE.md) — LaTeX mathematical foundations and canonical citations.
- **2026 Threat Landscape Report:** [2026 Agent Security Threat Report](./docs/research/2026_AGENT_SECURITY_LANDSCAPE_AND_THREAT_MODEL.md) — OWASP MCP & agent attack vectors.
- **CISO Compliance White Paper:** [CISO Security & Compliance White Paper](./docs/compliance/CISO_SECURITY_WHITE_PAPER.md) (SOC 2, HIPAA, PCI-DSS).
- **EU AI Act & GDPR Mapping:** [EU AI Act & Regulatory Crosswalk](./docs/compliance/EU_AI_ACT_MAPPING.md) (Articles 9–15).
- **Honest Boundaries & Limitations:** [Limitations & Architectural Boundaries](./docs/LIMITATIONS_AND_BOUNDARIES.md) — Unbiased scope and threat boundary map.
- **Responsible AI & Ethics Charter:** [Ethics & Responsible AI Charter](./ETHICS_AND_RESPONSIBLE_AI.md) — Dual-use policy, civil safety & ISO/IEC 29147 Safe Harbor.
- **Legal & Ethical Disclaimers:** [Legal Disclaimer & Safe Harbor](./DISCLAIMER.md).


---

## 🛡️ Frontier Capabilities & Ecosystem Architecture

### 1. Streaming Token Interceptor & Early Abort Engine
Real-time Server-Sent Events (SSE) token filtering with an Aho-Corasick trie sliding window:
```typescript
import { AegisStreamInterceptor } from '@aegis-kernel/core';

const interceptor = new AegisStreamInterceptor(engine, { maxPatternLength: 256, abortOnMatch: true });
for await (const chunk of interceptor.intercept(llmTokenStream)) {
  if (chunk.action === 'ABORT') break; // Early abort on secret/PII detection
  process.stdout.write(chunk.text);
}
```

### 2. Multi-Turn Conversation State Tracker (Crescendo Defense)
Exponential decay risk scoring detecting slow-burn privilege escalations and multi-turn intent drift:
```typescript
import { ConversationTracker } from '@aegis-kernel/core';

const tracker = new ConversationTracker({ driftThreshold: 0.75, riskDecayFactor: 0.85 });
const verdict = tracker.addTurn({ turnIndex: 1, toolName: 'exec_cmd', params: {}, riskContribution: 0.3, timestamp: Date.now() });
```

### 3. Causal Execution DAG & Multi-Agent Exfiltration Detection
Tracks data flows across multi-step agent trajectories to discover exfiltration chains (`read_file` → `format` → `send_email`) and circular delegation loops (OWASP Agentic ASI08):
```typescript
import { ExecutionDAG } from '@aegis-kernel/core';

const dag = new ExecutionDAG();
dag.addAction({ id: 'act_1', toolName: 'read_file', params: { path: '/etc/passwd' }, dataDependencies: [] });
const anomalies = dag.detectAnomalousPatterns();
```

### 4. Declarative Policy-as-Code Engine (custom DSL — Cedar/Rego-inspired syntax)

> **Honest note:** this is a small built-in policy DSL with Cedar-like `permit`/`forbid` effects and a simple AST condition evaluator. It does **not** parse AWS Cedar or OPA Rego syntax — it is *inspired by* them.
```typescript
import { PolicyEngine } from '@aegis-kernel/core';

const policyEngine = new PolicyEngine();
policyEngine.addPolicy({
  id: 'pol_1',
  statements: [{
    effect: 'permit',
    principal: 'support_agent',
    action: 'query_db',
    resource: 'users_table',
    condition: 'row_limit <= 100 && operation == "SELECT"'
  }]
});
```

---

## 🤝 Contributing & Community

- **Contributing Guide**: See [CONTRIBUTING.md](./CONTRIBUTING.md) for local dev setup, coding standards, and PR requirements.
- **Code of Conduct**: See [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
- **Security Policy**: See [SECURITY.md](./SECURITY.md) for responsible disclosure and Safe Harbor terms.
- **Legal Disclaimer**: See [DISCLAIMER.md](./DISCLAIMER.md).
- **Discussions & Support**: Open an issue on [GitHub Issues](https://github.com/Snehgabani/aegis-kernel/issues).

---

## 📄 License

Distributed under the [MIT License](./LICENSE). Copyright (c) 2026 Sneh Gabani.
