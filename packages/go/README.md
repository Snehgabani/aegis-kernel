# 🛡️ Aegis Invariant Kernel for Go

> **Deterministic Tool-Call Safety Gateway & Invariant Kernel for AI Agents in Go**  
> *Sub-Millisecond Latency • Zero Network Egress • Multi-Dialect SQL & State Invariants*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/aegis-kernel/aegis-go)](https://goreportcard.com/report/github.com/aegis-kernel/aegis-go)
[![Tests](https://img.shields.io/badge/tests-17%2F17%20passing-brightgreen.svg)](#)

---

## 🚀 Overview

`aegis-go` is the official native Go engine for the **Aegis Invariant Kernel**. It provides in-process, zero-network-egress deterministic clearance for LLM agent tool calls before execution.

### Key Capabilities:
- **Multi-Dialect SQL AST & Token Checker**: Blocks DDL (`DROP`, `TRUNCATE`, `ALTER TABLE ... DROP`), mass `DELETE`/`UPDATE` without `WHERE`, comment splits (`DEL/**/ETE`), zero-width Unicode injection, homoglyphs, and nested CTE mutations (`WITH ... AS (DELETE ...)`).
- **Principled Tautology Engine**: Detects constant-folding (`WHERE 1`, `WHERE 1=1`, `WHERE 2>1`), lower-bound identity tautologies (`WHERE id > 0`, `WHERE id != -1`), self-column comparisons (`WHERE id = id`), and unconstrained subqueries.
- **Numeric & Financial Aliases**: Strips formatted currency strings (`$5,000.00`, `€10,000`) and normalizes financial field aliases (`amount`, `total`, `price`, `payout`, `value`, `payment`, `transfer`) with default `min: 0`.
- **Salted PII Token Vault**: Session-salted deterministic HMAC-SHA256 tokenization and detokenization (`<US_SSN_...>`, `<CREDIT_CARD_...>`).
- **State Invariants & Multi-Tenant Isolation**: DSL expression parser evaluating state assertions (`params.amount <= state.balance`, `state.tenant_id == params.tenant_id`).
- **Cryptographic Merkle Audit Chain**: Tamper-evident SHA-256 Merkle root event ledger.

---

## 📦 Installation

```bash
go get github.com/aegis-kernel/aegis-go
```

---

## ⚡ Quickstart

```go
package main

import (
	"fmt"

	aegis "github.com/aegis-kernel/aegis-go"
)

func main() {
	// Initialize the Aegis Engine with default guard packs
	engine := aegis.NewDefaultEngine()

	// 1. Evaluate a dangerous mass DELETE tool call
	maliciousCall := aegis.ToolCall{
		Tool: "database_exec",
		Params: map[string]interface{}{
			"query": "DELETE FROM users WHERE 1=1",
		},
	}
	verdict := engine.Evaluate(maliciousCall)
	fmt.Printf("Malicious Call Allowed: %v (Violations: %d, Latency: %s)\n",
		verdict.Allowed, len(verdict.Violations), verdict.Latency)
	// Output: Malicious Call Allowed: false (Violations: 1, Latency: 450µs)

	// 2. Evaluate a safe targeted SELECT
	benignCall := aegis.ToolCall{
		Tool: "database_exec",
		Params: map[string]interface{}{
			"query": "SELECT id, name FROM users WHERE id = 42",
		},
	}
	verdict = engine.Evaluate(benignCall)
	fmt.Printf("Benign Call Allowed: %v (Latency: %s)\n",
		verdict.Allowed, verdict.Latency)
	// Output: Benign Call Allowed: true (Latency: 120µs)
}
```

---

## 🧪 Running Tests

```bash
cd packages/go
go test -v ./...
```
