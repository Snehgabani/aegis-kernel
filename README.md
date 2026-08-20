<div align="center">

# Aegis Invariant Kernel

**Deterministic safety verification for AI agent tool calls.**<br>
In-process AST analysis · <1.5ms latency · zero network egress · TypeScript & Python

<br>

[![CI](https://github.com/Snehgabani/aegis-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/Snehgabani/aegis-kernel/actions)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14173/badge)](https://www.bestpractices.dev/projects/14173)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-532%20passing-brightgreen.svg)](https://github.com/Snehgabani/aegis-kernel/actions)
[![npm](https://img.shields.io/badge/npm-@aegis--kernel%2Fcore-10b981.svg?logo=npm)](https://www.npmjs.com/package/@aegis-kernel/core)
[![PyPI](https://img.shields.io/badge/PyPI-aegis--kernel-10b981.svg?logo=pypi)](https://pypi.org/project/aegis-kernel/)

[Playground](https://snehgabani.github.io/aegis-kernel/playground/) · [Docs](https://snehgabani.github.io/aegis-kernel/docs/) · [Benchmarks](https://snehgabani.github.io/aegis-kernel/compare-nemo.html) · [White Paper](./WHITE_PAPER.md) · [Sponsor](https://github.com/sponsors/Snehgabani)

</div>

---

## What is Aegis?

Aegis is an open-source safety kernel that intercepts AI agent tool calls — database queries, financial transactions, API requests — and verifies them against deterministic invariants before execution. It parses SQL into abstract syntax trees, applies tautology detection via constant folding, enforces numeric bounds, and masks secrets through salted token vaults. All of this happens in-process, typically under 1.5ms for single-statement queries, with no external API calls and no LLM-as-judge dependency.

The core observation behind Aegis: conversational guardrails (toxicity filters, tone moderation) operate on natural language, but the most dangerous agent failures happen at the *tool boundary* — a `DROP TABLE`, an unbounded `DELETE`, a $500,000 wire transfer. These are structural violations, not linguistic ones, and they can be caught deterministically through AST analysis rather than probabilistic classification.

### Install

```bash
# TypeScript / Node.js
npm install @aegis-kernel/core

# Python 3.9+ (zero dependencies)
pip install aegis-kernel

# MCP (Claude Desktop, Cursor, Windsurf)
npx -y @smithery/cli install sneh-gabani1999/aegis-kernel --client claude
```

### Quickstart

**Python** — wrap any tool function with a single decorator:
```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="database_exec")
def execute_sql(query: str):
    # Blocks DROP TABLE, TRUNCATE, unconstrained DELETE automatically
    return db.execute(query)
```

**TypeScript** — wrap MCP or LangChain tool handlers:
```typescript
import { AegisMCPMiddleware } from '@aegis-kernel/mcp';

const middleware = new AegisMCPMiddleware({
  mode: 'enforce',
  packs: ['@aegis/sql-guard', '@aegis/data-guard']
});
const safeHandler = middleware.wrapToolHandler('database_query', handler);
```

**LangChain / CrewAI:**
```typescript
import { AegisLangChainGuard } from '@aegis-kernel/langchain';

const guard = new AegisLangChainGuard();
const protectedTool = guard.wrap(myExistingTool);
```

---

## How it works

Aegis operates as a four-tier verification pipeline between the agent's proposed action and actual execution:

```
  Agent proposes tool call
          │
          ▼
  ┌─────────────────────────────────────────────────────────┐
  │ Tier 1: Lexical normalization (<0.03ms)                 │
  │  Aho-Corasick token scanner · Unicode NFKD sanitizer   │
  │  Zero-width character stripping · Prompt injection      │
  │  heuristic (regex, not ML)                              │
  └────────────────────────┬────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────┐
  │ Tier 2: AST compilation & semantic validation (<0.15ms) │
  │  Multi-dialect SQL parser (Postgres, MySQL, SQLite,     │
  │  T-SQL) · Tautology constant-folding · Numeric range    │
  │  clamping · PII salted token vault · Policy DSL engine  │
  │  · WASM sandbox validator                               │
  └────────────────────────┬────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────┐
  │ Tier 3: Behavioral & temporal analysis (<0.06ms)        │
  │  Agent RBAC · Causal execution DAG · Crescendo drift    │
  │  tracker · Swarm budget ceilings · Circuit breaker      │
  └────────────────────────┬────────────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────┐
  │ Tier 4: Cryptographic commitment & explainability       │
  │  SHA-256 proofHash per event · Merkle audit ledger      │
  │  · EU AI Act Art. 13 explainer · Self-healing re-ask    │
  └────────────────────────┬────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
        ALLOWED (<1ms)           BLOCKED (<1ms)
    Execute + proof receipt   Self-healing feedback
```

Each tier is designed to fail closed: if any stage throws an internal error, the tool call is blocked by default. The entire hot path makes zero outbound network calls.

---

## What it catches

| Threat category | How Aegis handles it | Latency |
|:---|:---|:---|
| **SQL injection and mass data loss** (`DROP TABLE`, `TRUNCATE`, tautological `WHERE 1=1`) | Compiles SQL to AST, walks the tree for mutation nodes and tautological predicates via constant folding | <1.5ms |
| **SQL comment evasion** (`SELECT /* hidden */` to smuggle past string matching) | Strips all comment variants before AST analysis, including nested and multi-line | <0.5ms |
| **Financial overspend** (agent sets `amount: 999999`) | Exact BigInt arithmetic with configurable ceiling and velocity bounds per currency alias | <0.2ms |
| **Secret and PII exfiltration** (API keys, SSNs, credit cards in tool output) | Aho-Corasick streaming scanner with salted token vault — data never leaves process | <0.3ms |
| **Multi-turn privilege escalation** (crescendo attacks across conversation turns) | Exponential decay risk scoring detects slow-burn drift toward restricted operations | <0.1ms |
| **Cross-agent exfiltration chains** (`read_file` → `format` → `send_email`) | Causal DAG tracks data flow across multi-step agent trajectories | <0.1ms |

**Explicitly out of scope:** Aegis does not handle conversational tone moderation, hate speech detection, or multimodal content filtering. Those are best served by LLM-based systems like NeMo Guardrails or Llama Guard. Aegis is designed to complement them at the tool boundary.

> **🏗️ Feature Maturity Notes:**
> - **Zero-Knowledge Proofs:** The codebase uses SHA-256 **hash commitments**, not zk-SNARKs. True Groth16/PLONK proofs are on the roadmap.
> - **WASM Sandbox:** The `WasmPluginRunner` provides the interface architecture; actual WASM compilation/validation is coming in v1.1.0.
> - **Enclave Attestation:** `EnclaveAttestation` is a **development simulation** — set `AEGIS_ATTESTATION_MODE=production` to request real attestation (AWS Nitro/Intel SGX integration pending).
> See [LIMITATIONS_AND_BOUNDARIES.md](./docs/LIMITATIONS_AND_BOUNDARIES.md) and [ROADMAP.md](./docs/ROADMAP.md) for details.

---

## Benchmarks

Every published figure is traceable to a committed, reproducible artifact in **[benchmarks/EVIDENCE.md](./benchmarks/EVIDENCE.md)** (corrections register included). Canonical academic datasets (InjecAgent, AgentDojo) are supported via a fail-loud fetch-and-verify pipeline (`scripts/fetch-canonical-benchmarks.mjs`); headline numbers are reported in the field-standard metrics (ASR / defense rate / benign utility / risk).

| Benchmark | Dataset | Result |
|:---|:---|:---|
| InjecAgent (ACL 2024) | in-tree representative corpus (N=13) | 100% verdict agreement (ASR 0%, utility 100%) |
| InjecAgent-style synthetic expansion | Aegis-authored corpus (N=1,054, all attack vectors) | 100% attack block rate (defense rate 100%) |
| AgentDojo (NeurIPS 2024) | in-tree representative corpus (N=9) | 100% verdict agreement (ASR 0%, utility 100%) |
| Adversarial fuzz corpus | 433 vectors (300 malicious, 133 benign) | 0 bypasses, 0 false positives |
| Independent red-team audit | 32 vectors (25 adversarial + 7 benign controls) | 32/32 verified, 0 bypasses |
| Throughput (Apple Silicon) | Statistical benchmark harness | 2,861 ops/sec, P50 0.22ms, P95 4.74ms |
| Latency (per-workload, measured) | benign ≈ 0.037ms p50 · SQL simple ≈ 1.10ms · SQL complex ≈ 1.85ms | [evidence](./.benchmark/evidence.json) |
| Test suite | 76 files, TypeScript + Python + Go + Rust | 557/557 passing |
| Coverage | Core engine source | 84% statements, 85% lines |

> **Honesty note (2026-08-20):** earlier revisions of this README quoted
> "93.5% InjecAgent resilience" and "86.6% AgentDojo accuracy" as measured on the
> public academic datasets. Those numbers were **not reproducible from any
> dataset in this repository** and have been withdrawn and replaced by the
> corpus-provenanced figures above. Canonical-dataset runs are pending in
> network-enabled CI; none will be published until committed with checksummed
> artifacts. See `benchmarks/EVIDENCE.md` §3.

### How Aegis compares to other approaches

| | Aegis | NeMo Guardrails | Lakera Guard | Guardrails AI |
|:---|:---|:---|:---|:---|
| **Evaluation method** | Deterministic AST + schema | Heuristic / Colang LLM | Cloud ML classifiers | RAIL regex / LLM judge |
| **Typical latency** | 0.15–0.55ms (in-memory) | 15–60ms (GPU) | ~50ms (cloud API) | 50–300ms (Python) |
| **Network dependency** | None (fully in-process) | Cloud / GPU | Outbound API | Cloud LLM |
| **MCP support** | Native JSON-RPC 2.0 | No | No | No |
| **TypeScript native** | Yes | No (Python only) | No (REST API) | Wrapper only |

> *Competitor figures reflect vendor-published benchmarks. Trademarks (NVIDIA NeMo Guardrails, Lakera Guard, Guardrails AI) belong to their respective holders; usage does not imply affiliation or endorsement.*

---

## Where Aegis fits in your stack

Aegis is designed to run as the second stage in a defense-in-depth pipeline:

```
  User input
      │
      ▼
  Stage 1: Conversational moderation (LLM judge)
  Toxicity, hate speech, brand tone — powered by
  Llama Guard, NeMo Guardrails, or your own model.
      │
      ▼
  LLM Agent proposes tool action
      │
      ▼
  Stage 2: Aegis deterministic clearance (<1.5ms)
  SQL AST, numeric bounds, PII masking, state
  invariants, cryptographic audit proof.
      │
      ├──→ BLOCKED: self-healing feedback to agent
      └──→ ALLOWED: execute + SHA-256 proof receipt
```

---

## Language support

| Language | Status | What it covers |
|:---|:---|:---|
| **TypeScript / Node.js** | Core engine | Full AST parsing, JSON schema compilation, Merkle audit chain, CLI, MCP middleware, live playground |
| **Python (≥3.9)** | Native engine, zero deps | SQL token parsing, financial aliases, PII vault, state DSL, framework adapters (CrewAI, AutoGen, LangChain) |
| **Go (≥1.21)** | Native engine | SQL token/AST validation, comment de-obfuscation, tautology engine, PII vault, state DSL |
| **Rust (≥1.75)** | Native crate | Zero-allocation SQL invariant checker, tautology folding, HMAC token vault, policy commitment circuit |

> Go and Rust SDKs cover a subset of checks and are not full ports of the TypeScript engine. See each package's README for exact scope.

### Build from source

```bash
git clone https://github.com/Snehgabani/aegis-kernel.git
cd aegis-kernel
npm install
npm run build   # builds all workspace packages (tsup)
npm test        # 532/532 tests, 74 suites
```

---

## Reference architectures

Working examples for common agent deployment patterns:

| Architecture | Domain | Key defense | Source |
|:---|:---|:---|:---|
| CrewAI Financial Analyst | Fintech | Comment-split SQL evasion + $10K disbursement ceiling | [`examples/crewai-financial-analyst`](./examples/crewai-financial-analyst) |
| LangGraph Multi-Agent | Enterprise | Cross-agent privilege escalation + self-healing loops | [`examples/langgraph-multi-agent`](./examples/langgraph-multi-agent) |
| FastAPI MCP Gateway | Microservices | Zero-trust JSON-RPC schema pinning | [`examples/fastapi-mcp-gateway`](./examples/fastapi-mcp-gateway) |
| OpenAI Tool-Calling Agent | Analytics | Tautology folding + mass DELETE prevention | [`examples/openai-sql-agent`](./examples/openai-sql-agent) |
| Quantitative Trading Guard | Algo trading | Max-drawdown velocity bounds + order-size clamping | [`examples/python-trading-guard`](./examples/python-trading-guard) |

---

## CLI

```bash
npx aegis init                    # create aegis.config.yaml
npx aegis doctor                  # health check across all subsystems
npx aegis eval all --output e.json # academic benchmarks (InjecAgent, AgentDojo)
npx aegis scan .                  # scan workspace for prompt injection threats
npx aegis test                    # security bounds testbed
npx aegis repl                    # interactive evaluation REPL
npx aegis benchmark --tricky      # statistical benchmark harness
npx aegis audit-report .          # SOC 2 / ISO 42001 self-assessment report
npx aegis explain execute_sql '{"query": "DROP TABLE users"}'
npx aegis stats                   # real-time latency dashboard
npx aegis diagnose execute_sql '{"query": "DELETE FROM users"}'
```

---

## Advanced capabilities

### Streaming token interceptor

Real-time SSE token filtering with Aho-Corasick trie sliding window. Aborts the stream early on secret or PII detection:

```typescript
import { AegisStreamInterceptor } from '@aegis-kernel/core';

const interceptor = new AegisStreamInterceptor(engine, {
  maxPatternLength: 256,
  abortOnMatch: true
});
for await (const chunk of interceptor.intercept(llmTokenStream)) {
  if (chunk.action === 'ABORT') break;
  process.stdout.write(chunk.text);
}
```

### Multi-turn conversation tracker (crescendo defense)

Exponential decay risk scoring for slow-burn privilege escalation:

```typescript
import { ConversationTracker } from '@aegis-kernel/core';

const tracker = new ConversationTracker({
  driftThreshold: 0.75,
  riskDecayFactor: 0.85
});
const verdict = tracker.addTurn({
  turnIndex: 1,
  toolName: 'exec_cmd',
  params: {},
  riskContribution: 0.3,
  timestamp: Date.now()
});
```

### Causal execution DAG

Tracks data flows across multi-step agent trajectories. Detects exfiltration chains and circular delegation loops (OWASP Agentic Top 10 ASI08):

```typescript
import { ExecutionDAG } from '@aegis-kernel/core';

const dag = new ExecutionDAG();
dag.addAction({
  id: 'act_1',
  toolName: 'read_file',
  params: { path: '/etc/passwd' },
  dataDependencies: []
});
const anomalies = dag.detectAnomalousPatterns();
```

### Policy-as-code engine

A built-in DSL with Cedar-inspired `permit`/`forbid` effects and a simple AST condition evaluator. (This is not an AWS Cedar or OPA Rego parser — it draws on similar concepts.)

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

## CI/CD integration

Add Aegis as a GitHub Action to audit tool invariants on every pull request:

```yaml
- name: Aegis Security Audit
  uses: Snehgabani/aegis-kernel@v1
  with:
    config-path: "./aegis.config.yaml"
    mode: "enforce"
    generate-report: "true"
```

---

## Security model

- **Fail-closed by default.** Internal errors block the tool call. Set `failPolicy: 'fail-open'` explicitly only if availability matters more than safety for a given pack.
- **Zero network egress.** The clearance hot path makes no outbound calls. Air-gapped deployments work without modification.
- **WASM plugins are fail-closed.** A module that doesn't export `validate()` is treated as invalid.
- **Cryptographic audit trail.** Every clearance decision emits a 14-field privacy-safe event with an immutable SHA-256 `proofHash` binding tool arguments to policy hashes.

### Compliance tooling

Aegis generates compliance **self-assessment** evidence exports for SOC 2, HIPAA, and ISO 42001 control frameworks. This is documentation tooling, not a certification — SOC 2 certification requires an independent CPA audit. See [COMPLIANCE_SELF_ASSESSMENT.md](./docs/COMPLIANCE_SELF_ASSESSMENT.md).

### Red-team challenge

We invite security researchers to test the kernel's deterministic boundaries. Craft a SQL payload under standard `@aegis/sql-guard` rules that bypasses AST comment-stripping, tautology folding, and mutation checks to execute unauthorized `DROP TABLE`, `TRUNCATE`, or unconstrained `DELETE/UPDATE`.

Report via [GitHub Security Advisories](https://github.com/Snehgabani/aegis-kernel/security/advisories/new) or `security@aegis-kernel.dev`. Verified bypasses receive CVE attribution and permanent recognition.

---

## Documentation

- [Getting Started](./docs/GETTING_STARTED.md) — Installation, quickstart, and integration tutorials
- [API Reference](./docs/API_REFERENCE.md) — Exhaustive public classes, inputs, outputs, REST endpoints, and CLI options
- [Security User Guide](./docs/SECURITY_USER_GUIDE.md) — Secure configuration, operational dos and don'ts
- [White Paper](./WHITE_PAPER.md) — Technical report with threat model and formal proofs
- [Interactive Playground](https://snehgabani.github.io/aegis-kernel/playground/) — Test invariants live in the browser
- [Architecture Docs](https://snehgabani.github.io/aegis-kernel/docs/) — Searchable API and policy reference
- [Audit Dashboard](https://snehgabani.github.io/aegis-kernel/dashboard/) — Live audit stream with CSV export
- [Supply Chain Trust & Provenance](./docs/security/SUPPLY_CHAIN_TRUST_AND_PROVENANCE.md) — SLSA L3, Sigstore signing, SBOM & reproducible builds
- [Elite Automation & Supply Chain Governance](./docs/architecture/ELITE_AUTOMATION_AND_SUPPLY_CHAIN_GOVERNANCE.md) — 4-Tier bot mesh, Dependabot topology & continuous assurance
- [Security Capabilities & Permissions Disclosure](./docs/compliance/SECURITY_CAPABILITIES_DISCLOSURE.md) — Socket.dev capability disclosure & dependency justification
- [OpenSSF Best Practices Evidence](./docs/compliance/OPENSSF_BEST_PRACTICES_EVIDENCE.md) — Criteria mapping for OpenSSF Badge #14173
- [Limitations and Boundaries](./docs/LIMITATIONS_AND_BOUNDARIES.md) — Honest scope and architectural constraints
- [EU AI Act Mapping](./docs/compliance/EU_AI_ACT_MAPPING.md) — Articles 9–15 crosswalk
- [Formal Specification](./docs/research/FORMAL_SPECIFICATION_AND_SYSTEM_ARCHITECTURE.md) — LaTeX mathematical foundations
- [2026 Threat Landscape Report](./docs/research/2026_AGENT_SECURITY_LANDSCAPE_AND_THREAT_MODEL.md) — OWASP MCP attack vectors
- [Privacy Policy](./PRIVACY.md) — Zero-egress data handling
- [Ethics Charter](./ETHICS_AND_RESPONSIBLE_AI.md) — Dual-use policy and civil safety
- [Telemetry](./TELEMETRY.md) — Anonymous metrics, opt-out guide, GDPR compliance

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup, coding standards, and PR requirements. Read [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) before participating. Report vulnerabilities per [SECURITY.md](./SECURITY.md).

Questions and bug reports: [GitHub Issues](https://github.com/Snehgabani/aegis-kernel/issues)

---

## License

MIT · Copyright (c) 2026 Sneh Gabani
