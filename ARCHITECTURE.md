# Aegis Invariant Kernel: Enterprise System Architecture

> For the publication-grade mathematical specification, latency budgets, and formalisms, see the [Comprehensive System Architecture Deep Dive](./docs/architecture/SYSTEM_ARCHITECTURE_DEEP_DIVE.md).

## 1. 4-Tier Zero-Egress Invariant Pipeline

```
                                ┌────────────────────────────────────────┐
                                │       AI Agent / LLM Orchestrator      │
                                └───────────────────┬────────────────────┘
                                                    │ ToolCall (JSON-RPC)
                                                    ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 AEGIS DETERMINISTIC INVARIANT KERNEL                             │
│                                      (P50 < 0.25ms, Zero Egress)                                 │
│                                                                                                  │
│  ┌─────────────────────────┐  ┌─────────────────────────┐  ┌──────────────────────────────────┐  │
│  │ Tier 1: Lexical Guard   │  │ Tier 2: Structural AST  │  │ Tier 3: Context & Topology       │  │
│  │ • Aho-Corasick Streams  │  │ • Multi-Dialect SQL AST │  │ • Agent Identity & RBAC          │  │
│  │ • Unicode Normalization │  │ • Numeric Risk Bounds   │  │ • Ed25519 Biscuit Tokens         │  │
│  │ • Secret Masking        │  │ • Policy-as-Code Engine │  │ • Causal Execution DAG           │  │
│  │ • Prompt Injection Scan │  │ • WASM Sandbox Plugins  │  │ • Crescendo Multi-Turn Tracker   │  │
│  └────────────┬────────────┘  └────────────┬────────────┘  └────────────────┬─────────────────┘  │
│               │                            │                                │                    │
│               ▼                            ▼                                ▼                    │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ Tier 4: Cryptographic Proofs, Self-Healing AST Fixes & Enterprise GRC Dossier             │  │
│  │ • SHA-256 ProofHash Commitments       • Tamper-Proof Merkle Chains                         │  │
│  │ • Plain-English EU AI Act Explanations • SIEM CEF/Syslog & STIX 2.1 CTI Threat Sharing    │  │
│  └─────────────────────────────────────────┬──────────────────────────────────────────────────┘  │
│                                            │                                                     │
│                    ┌───────────────────────┴───────────────────────┐                             │
│                    ▼                                               ▼                             │
│       ┌────────────────────────┐                      ┌────────────────────────┐                 │
│       │   ALLOW: Proof Hash    │                      │   BLOCK / REASK        │                 │
│       │   SHA-256 State Tree   │                      │   Self-Healing AST Fix │                 │
│       └────────────┬───────────┘                      └────────────┬───────────┘                 │
└────────────────────┼───────────────────────────────────────────────┼─────────────────────────────┘
                     │                                               │
                     ▼                                               ▼
        ┌─────────────────────────┐                     ┌─────────────────────────┐
        │ Target System / Tool DB │                     │ SIEM (CEF/Splunk/Syslog)│
        │ Clean Execution Payload │                     │ STIX 2.1 CTI Sharing    │
        └─────────────────────────┘                     └─────────────────────────┘
```


---

## 2. Monorepo Structure & Package Topology

- **`packages/core`**: Zero-egress deterministic invariant engine, AST checkers, Ed25519 Biscuit token monotonicity verifiers, and SHA-256 policy commitment generators.
- **`packages/diagnostics`**: Runtime health check suite, diagnostic probes, and version upgrade compatibility engine.
- **`packages/cli`**: Developer toolchain (`aegis scan`, `aegis replay`, `aegis doctor`, `aegis hub`, `aegis pack`).
- **`packages/mcp`**: Model Context Protocol (MCP) JSON-RPC safety clearance middleware and tool poisoning scanners.
- **`packages/evals`**: 100-vector adversarial stress testbed and 50-vector regression benchmark suite.
- **`packages/langchain` / `packages/openai` / `packages/anthropic`**: Framework adapters providing native pre-execution hooks.
- **`packages/python`**: Python SDK and async decorator reference implementation.
- **`services/gateway`**: Edge-deployable Cloudflare Workers / Hono gateway with Stripe billing webhooks and Prometheus metrics.
- **`services/control-plane`**: Central policy distribution and telemetry aggregation service with HMAC tenant isolation.

---

## 3. Cryptographic Invariants & Guarantees

1. **Policy Commitment Proofs**:
   - `PolicyCommitmentVerifier` deterministically generates SHA-256 commitments linking tool parameters against rule constraints without revealing private bounds.
2. **Biscuit Token Attenuation**:
   - Monotonic attenuation guarantee: child tokens can only narrow permissions, never expand. Every block in the chain is validated against parent rights.
3. **Immutable Audit Trail**:
   - `computeEventChainMerkleRoot` (in `grc-exporter.ts`) chains ordered events with `previousRootHash` into a Merkle root for tamper-evident GRC dossier exports. **Scope note:** this runs on the GRC export path — the main event ledger stores per-event SHA-256 `proofHash` commitments rather than a continuous Merkle chain.
4. **Zero-Egress Assurance**:
   - The core clearance pipeline performs zero outbound network calls by default, guaranteeing zero latency jitter and zero conversational prompt leakage.

---

## 4. Diagnostics & Continuous Health Monitoring

- **CLI Doctor**: `npx aegis doctor` performs live subsystem checks and outputs structured health scores.
- **In-Process Self-Test**: `engine.runSelfTest()` provides instantaneous in-memory verification.
- **Readiness Probes**: `GET /health/deep` exposes real-time engine probe telemetry for Kubernetes and cloud orchestrators.
- **Automated CI**: GitHub Actions runs Node (20.x, 22.x) and Python (3.9–3.12) matrices, live E2E operational proofs, and Dependabot weekly maintenance.
