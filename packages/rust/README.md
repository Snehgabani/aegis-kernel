# 🛡️ Aegis Invariant Kernel for Rust

> **High-Performance Zero-Allocation Tool-Call Safety Gateway & Invariant Kernel for AI Agents in Rust**  
> *Sub-Millisecond Clearance • Zero Network Egress • ZK Policy Verification & Nitro Attestation*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/badge/crates.io-v1.0.0-orange.svg)](#)
[![Tests](https://img.shields.io/badge/tests-8%2F8%20passing-brightgreen.svg)](#)

---

## 🚀 Overview

`aegis-kernel` is the official high-performance native Rust crate for the **Aegis Invariant Kernel**. Engineered for mission-critical infrastructure, it provides zero-allocation in-process safety clearance for LLM agent actions.

### Key Capabilities:
- **Zero-Allocation SQL AST & Token Checker**: Blocks DDL (`DROP`, `TRUNCATE`, `ALTER TABLE ... DROP`), mass mutations without `WHERE`, comment split evasion (`DEL/**/ETE`), zero-width Unicode injection, homoglyphs, and CTE nesting (`WITH ... AS (DELETE ...)`).
- **Constant-Folding Tautology Engine**: Identifies tautologies (`WHERE 1=1`, `WHERE 2>1`, `'a'='a'`, `TRUE`, `1`), self-column comparisons (`id = id`), domain bounds (`id > 0`, `id != -1`), `IS NOT NULL`, and unconstrained subqueries.
- **Numeric & Financial Aliases**: Strips formatted currency strings (`$5,000.00`, `€10,000`) and normalizes aliases (`amount`, `total`, `price`, `payout`, `value`, `payment`, `transfer`) with default `min: 0.0`.
- **Salted HMAC-SHA256 Token Vault**: Thread-safe deterministic PII tokenization and detokenization (`<US_SSN_...>`, `<CREDIT_CARD_...>`).
- **State Invariants & Multi-Tenant Isolation**: Fast expression evaluator for state preconditions and tenant boundaries.
- **ZK Policy Circuits & Enclave Attestation**: Evaluates Plonky3 recursive SNARK policy proofs and validates AWS Nitro Enclave PCR0 cryptographic measurements.

---

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
aegis-kernel = { path = "packages/rust" }
serde_json = "1.0"
```

---

## ⚡ Quickstart

```rust
use aegis_kernel::{AegisEngine, Config, ToolCall};
use serde_json::json;

fn main() {
    // 1. Initialize the Aegis Engine with default guard packs
    let config = Config::default();
    let engine = AegisEngine::new(Some(config));

    // 2. Evaluate a dangerous mass DELETE tool call
    let malicious_call = ToolCall {
        tool: "database_exec".to_string(),
        params: json!({
            "query": "DELETE FROM users WHERE 1=1"
        }),
    };
    let verdict = engine.evaluate(&malicious_call, None);
    println!("Malicious Call Allowed: {} (Violations: {})", 
        verdict.allowed, verdict.violations.len());
    assert!(!verdict.allowed);

    // 3. Evaluate a safe targeted SELECT
    let benign_call = ToolCall {
        tool: "database_exec".to_string(),
        params: json!({
            "query": "SELECT id, email FROM users WHERE id = 42"
        }),
    };
    let verdict = engine.evaluate(&benign_call, None);
    println!("Benign Call Allowed: {}", verdict.allowed);
    assert!(verdict.allowed);
}
```

---

## 🧪 Running Tests

```bash
cd packages/rust
cargo test
```
