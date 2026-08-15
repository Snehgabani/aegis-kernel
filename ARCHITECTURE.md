# Aegis Invariant Kernel: Enterprise System Architecture

## 1. Zero-Trust Invariant Model

```
                               ┌────────────────────────────────────────┐
                               │       AI Agent / LLM Orchestrator      │
                               └───────────────────┬────────────────────┘
                                                   │ ToolCall (JSON-RPC)
                                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 AEGIS DETERMINISTIC INVARIANT KERNEL                             │
│                                                                                                  │
│  ┌─────────────────────────┐  ┌─────────────────────────┐  ┌──────────────────────────────────┐  │
│  │   Agent Identity & RBAC │  │   SQL AST Parser        │  │   PII Anonymization Vault        │  │
│  │   Ed25519 Biscuit Tokens│  │   Postgres/MySQL/SQLite │  │   16-byte HMAC Salt Tokenizer    │  │
│  └────────────┬────────────┘  └────────────┬────────────┘  └────────────────┬─────────────────┘  │
│               │                            │                                │                    │
│               ▼                            ▼                                ▼                    │
│  ┌────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                       Zero-Egress Deterministic Evaluation Engine                          │  │
│  │                                 (<0.5ms Execution Latency)                                 │  │
│  └─────────────────────────────────────────┬──────────────────────────────────────────────────┘  │
│                                            │                                                     │
│                    ┌───────────────────────┴───────────────────────┐                             │
│                    ▼                                               ▼                             │
│       ┌────────────────────────┐                      ┌────────────────────────┐                 │
│       │   ALLOW: Proof Hash    │                      │   BLOCK: Violation     │                 │
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
   - `computeEventChainMerkleRoot` links successive event trees with `previousRootHash` for non-repudiable SOC 2 Type II and ISO 42001 compliance dossiers.
4. **Zero-Egress Assurance**:
   - The core clearance pipeline performs zero outbound network calls by default, guaranteeing zero latency jitter and zero conversational prompt leakage.

---

## 4. Diagnostics & Continuous Health Monitoring

- **CLI Doctor**: `npx aegis doctor` performs live subsystem checks and outputs structured health scores.
- **In-Process Self-Test**: `engine.runSelfTest()` provides instantaneous in-memory verification.
- **Readiness Probes**: `GET /health/deep` exposes real-time engine probe telemetry for Kubernetes and cloud orchestrators.
- **Automated CI**: GitHub Actions runs Node (20.x, 22.x) and Python (3.9–3.12) matrices, live E2E operational proofs, and Dependabot weekly maintenance.
