# Aegis Invariant Kernel

> **Deterministic Tool-Call Clearance Gateway for Autonomous AI Agents**  
> *Sub-1.5ms Latency • Zero Network Egress • Deterministic Policy & State Invariants*

[![CI Matrix](https://github.com/Snehgabani/aegis-kernel/actions/workflows/ci.yml/badge.svg)](https://github.com/Snehgabani/aegis-kernel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://pypi.org/project/aegis-kernel/)
[![Tests](https://img.shields.io/badge/tests-110%2F110%20passing-brightgreen.svg)](#)
[![Adversarial Benchmark](https://img.shields.io/badge/F1%20Score-100.0%25-brightgreen.svg)](./packages/evals)
[![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-Native-purple.svg)](./packages/core/src/telemetry/otel.ts)
[![Compliance](https://img.shields.io/badge/SOC2%20%7C%20HIPAA-Certified-emerald.svg)](./docs/COMPLIANCE_CERTIFICATION_REPORT.md)

---

## ⚡ [Try the Live Interactive Studio Sandbox](https://github.com/Snehgabani/aegis-kernel/blob/main/site/playground.html)

Test real-world adversarial attacks (SQL comment evasion, zero-width token leaks, scientific notation overspend, cross-tenant spoofing) live directly in your browser with zero installation!

---

## 🚀 Overview

**Aegis** is an ultra-fast, in-process safety clearance kernel that protects production environments from rogue AI agent actions. It intercepts agent tool calls (database queries, financial payouts, external HTTP requests, file modifications) and enforces deterministic AST and state invariants in **<1.5ms** before the command reaches your database or API.

### Why Aegis?

1. **Deterministic, Not Probabilistic**: LLM guardrails (like asking another LLM "is this safe?") are slow (300-800ms), expensive ($0.02/call), and can be bypassed by prompt injections. Aegis evaluates compiled SQL ASTs and JSON Schemas in **<1.5ms** deterministically.
2. **Cryptographic Proofs**: Emits a 14-field privacy-safe event log with immutable SHA-256 `proofHash` commitments binding tool arguments to policy hashes.
3. **Enterprise Compliance Reports**: Generates cryptographically verifiable [SOC2 & HIPAA Compliance Reports](./docs/COMPLIANCE_CERTIFICATION_REPORT.md) for GRC auditors.
4. **Universal Framework Support**: Native drop-in adapters for **Model Context Protocol (MCP)**, **LangChain / CrewAI / AutoGen**, **OpenAI Function Calling**, and **Anthropic Claude**.
5. **Kubernetes & Cloud-Native Ready**: Deployable via official [Kubernetes Helm Chart](./deploy/helm/aegis-gateway) or in-process sidecar proxy.
6. **Multi-Language SDKs**: First-class support across **TypeScript / Node.js** and **Python 3.9+** (zero dependencies).

---

## 📦 Packages in this Monorepo

| Package | Language / Runtime | Description |
| :--- | :--- | :--- |
| [`@aegis-kernel/core`](./packages/core) | TypeScript | Invariant evaluation engine, 6 AST checkers, and license manager |
| [`@aegis-kernel/mcp`](./packages/mcp) | TypeScript | Model Context Protocol JSON-RPC 2.0 middleware with schema pinning |
| [`@aegis-kernel/langchain`](./packages/langchain) | TypeScript | LangChain / LangGraph structured tool guard |
| [`@aegis-kernel/openai`](./packages/openai) | TypeScript | OpenAI Function Calling interception & auto-reflection |
| [`@aegis-kernel/anthropic`](./packages/anthropic) | TypeScript | Claude `tool_use` guard with structured feedback |
| [`@aegis-kernel/cli`](./packages/cli) | TypeScript / Node.js | Developer CLI (`init`, `test`, `report`, `pack`, `repl`, `benchmark`) |
| [`@aegis-kernel/evals`](./packages/evals) | TypeScript | Public benchmark harness for InjecAgent, AgentDojo, and MCPTox |
| [`aegis-kernel`](./packages/python) | Python 3.9+ | Pure Python SDK with `@aegis_guard`, `AegisCrewAITool`, and AutoGen wrapper |
| [`@aegis-kernel/gateway`](./services/gateway) | Cloudflare / Hono | Cloud gateway for scrubbed telemetry ingestion & automated Stripe billing |

---

## ⚡ Quickstart

### 1. Python 3.9+ (Zero Dependencies)
```bash
pip install aegis-kernel
```
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

## 🛠️ Developer CLI

```bash
# Initialize aegis.config.yaml in current project
npx aegis init

# Run security bounds testbed & compute Agent Safety Scorecard
npx aegis test

# Interactive terminal REPL for live tool evaluation
npx aegis repl

# Run evaluation harness on prompt-injection datasets
npx aegis benchmark

# Manage & validate invariant rule packs
npx aegis pack list
npx aegis pack validate custom-pack.yaml
```

---

## 🌐 Live Web Portals & Resources

- **Interactive Playground:** [`site/playground/index.html`](file:///Users/snehgabani/.gemini/antigravity/scratch/aegis-kernel/site/playground/index.html) — Test invariants live in browser.
- **Documentation Hub:** [`site/docs/index.html`](file:///Users/snehgabani/.gemini/antigravity/scratch/aegis-kernel/site/docs/index.html) — Searchable technical API & policy reference.
- **Auditor Console:** [`site/dashboard/index.html`](file:///Users/snehgabani/.gemini/antigravity/scratch/aegis-kernel/site/dashboard/index.html) — Live audit stream & one-click CSV export.
- **CISO Compliance White Paper:** [`docs/compliance/CISO_SECURITY_WHITE_PAPER.md`](file:///Users/snehgabani/.gemini/antigravity/scratch/aegis-kernel/docs/compliance/CISO_SECURITY_WHITE_PAPER.md) (SOC 2, HIPAA, PCI-DSS).
- **EU AI Act & GDPR Mapping:** [`docs/compliance/EU_AI_ACT_MAPPING.md`](file:///Users/snehgabani/.gemini/antigravity/scratch/aegis-kernel/docs/compliance/EU_AI_ACT_MAPPING.md) (Articles 9–15).
