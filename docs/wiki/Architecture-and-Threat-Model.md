# 🏛️ Architecture & Threat Model

Aegis Invariant Kernel operates as an in-process, deterministic policy firewall situated directly between an Autonomous AI Agent and its Tool Execution Runtime.

---

## 🔒 4-Tier Defense Pipeline

```
[Agent LLM] ──> Tool Call Intent 
                      │
                      ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Tier 1: Identity & Attenuation Check                    │
 │ • Ed25519 Cryptographic Biscuit Tokens                  │
 │ • Monotonic capability attenuation across subagents     │
 └────────────────────────────┬────────────────────────────┘
                              │
 ┌────────────────────────────▼────────────────────────────┐
 │ Tier 2: Static Schema & Poisoning Detection             │
 │ • MCP Tool Schema Homoglyph & Hidden Unicode Inspection │
 │ • Prompt Injection Classifier ($O(N)$ linear tokens)    │
 └────────────────────────────┬────────────────────────────┘
                              │
 ┌────────────────────────────▼────────────────────────────┐
 │ Tier 3: Deterministic AST & Semantic Parsers            │
 │ • SQL AST parsing (node-sql-parser + regex fallback)    │
 │ • Strict Numeric Boundary & Slippage Bounds             │
 │ • Deterministic PII Masking & Token Vault               │
 └────────────────────────────┬────────────────────────────┘
                              │
 ┌────────────────────────────▼────────────────────────────┐
 │ Tier 4: Zero-Egress Cryptographic Evidence Log          │
 │ • Append-only SHA-256 Merkle Audit Chain                │
 │ • GRC Dossier generation (SOC2, HIPAA, EU AI Act)       │
 └────────────────────────────┬────────────────────────────┘
                              │
                      [Decision: Allow / Deny]
                              │
                              ▼
                 [External Tool Execution / MCP]
```

---

## 🛡️ Zero-Egress Core Invariant

The core evaluation package (`@aegis-kernel/core`) has **zero network dependencies** and makes no outbound network requests during evaluation. This guarantees:
1. **Air-Gapped Operation**: Run securely in confidential VMs, Kubernetes air-gapped enclaves, or private banking clusters.
2. **ReDoS Immunity**: All pattern checkers use deterministic linear algorithms avoiding polynomial regex backtracking.
3. **Deterministic Reproducibility**: Given the same policy config and tool call input, Aegis produces identical decisions and cryptographic Merkle hashes.
