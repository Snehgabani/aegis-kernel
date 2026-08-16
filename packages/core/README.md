# 🛡️ @aegis-kernel/core

> **Core Deterministic Invariant Clearance Engine for AI Agent Tool Calls**  
> *Sub-1.5ms Latency • Zero Network Egress • Deterministic AST & State Invariants*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0-green.svg)](https://nodejs.org/)

---

## 🚀 Overview

`@aegis-kernel/core` is the foundational TypeScript/Node.js engine of the **Aegis Invariant Kernel**. It intercepts LLM agent tool calls and enforces deterministic security, data integrity, and compliance policies in-process before actions reach databases or third-party APIs.

### Core Capabilities:
- **Multi-Dialect SQL AST Guard**: Blocks destructive DDL (`DROP`, `TRUNCATE`, `ALTER TABLE ... DROP`), mass `DELETE`/`UPDATE` without `WHERE`, comment splits (`DEL/**/ETE`), zero-width Unicode injection, and nested CTE mutations.
- **Deep Tautology Constant-Folding Engine**: Detects constant-folding (`WHERE 1`, `WHERE 1=1`, `WHERE 2>1`), lower-bound identity tautologies (`WHERE id > 0`, `WHERE id != -1`), and unconstrained subqueries.
- **Numeric & Financial Ceilings**: Strips formatted currency strings (`$5,000.00`, `€10,000`) and normalizes parameter aliases (`amount`, `total`, `price`, `payout`, `value`).
- **Salted PII Token Vault**: Session-salted deterministic HMAC-SHA256 tokenization and detokenization (`<US_SSN_...>`, `<CREDIT_CARD_...>`).
- **Causal Execution DAG & Drift Tracking**: Multi-turn exfiltration chain detection and exponential decay risk drift tracking.
- **Cryptographic Audit Ledger**: Immutable SHA-256 `proofHash` commitments and Ed25519/HMAC signed Merkle root event chains.

---

## 📦 Installation

```bash
npm install @aegis-kernel/core
```

---

## ⚡ Quickstart

### 1. Basic Invariant Evaluation

```typescript
import { AegisEngine } from '@aegis-kernel/core';

const engine = new AegisEngine({
  mode: 'enforce',
  failPolicy: 'fail-closed',
  packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard'],
});

// 1. Evaluate a dangerous mass DELETE
const verdict = engine.evaluate({
  tool: 'database_query',
  params: { sql: 'DELETE FROM accounts WHERE 1=1;' },
});

console.log(verdict.allowed); // false
console.log(verdict.violations); // [{ ruleId: 'SQL-001', message: 'SQL DELETE contains constant tautology WHERE clause' }]
console.log(verdict.proofHash); // SHA-256 cryptographic receipt

// 2. Evaluate a safe targeted query
const safeVerdict = engine.evaluate({
  tool: 'database_query',
  params: { sql: 'SELECT id, balance FROM accounts WHERE id = 1001 LIMIT 1;' },
});

console.log(safeVerdict.allowed); // true
```

### 2. Streaming Token Interceptor

```typescript
import { AegisEngine, AegisStreamInterceptor } from '@aegis-kernel/core';

const engine = new AegisEngine();
const interceptor = new AegisStreamInterceptor(engine, {
  maxPatternLength: 256,
  abortOnMatch: true,
});

for await (const chunk of interceptor.intercept(llmTokenStream)) {
  if (chunk.action === 'ABORT') {
    console.error('Stream aborted: Secret or PII leak detected!');
    break;
  }
  process.stdout.write(chunk.text);
}
```

### 3. Salted PII Token Vault

```typescript
import { PiiTokenVault } from '@aegis-kernel/core';

const vault = new PiiTokenVault({ salt: 'secure-session-salt-128bit' });

const masked = vault.tokenize('User SSN is 000-12-3456');
// Output: 'User SSN is <US_SSN_a9f8c7...>'

const original = vault.detokenize(masked);
// Output: 'User SSN is 000-12-3456'
```

---

## 📄 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT). Copyright (c) 2026 Sneh Gabani.
