# 🛡️ @aegis-kernel/mcp

> **Model Context Protocol (MCP) JSON-RPC 2.0 Safety Clearance Middleware**  
> *Tool Schema Pinning • Rug-Pull Detection • In-Process Deterministic Pre-Execution Clearance*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0-green.svg)](https://nodejs.org/)

---

## 🚀 Overview

`@aegis-kernel/mcp` provides native safety clearance middleware for **Model Context Protocol (MCP)** servers and clients. It intercepts JSON-RPC 2.0 `tools/call` requests, verifies schema stability (preventing tool poisoning and rug-pull attacks), and validates argument invariants in sub-1.5ms.

### Key Capabilities:
- **Zero-Latency Invariant Clearance**: Validates SQL ASTs, numeric ranges, and PII patterns on tool arguments.
- **MCP Schema Pinning**: Computes cryptographic SHA-256 hashes of tool schemas upon initialization to detect runtime drift or malicious schema replacement.
- **Output Sanitization**: Automatically scans and masks leaked secrets and PII from tool outputs before returning results to the LLM.
- **Confused-Deputy Defense**: Propagates caller identity tokens to ensure tenant-isolated tool access.

---

## 📦 Installation

```bash
npm install @aegis-kernel/mcp @aegis-kernel/core
```

---

## ⚡ Quickstart

```typescript
import { AegisMCPMiddleware } from '@aegis-kernel/mcp';

// 1. Initialize MCP Middleware with policy packs
const middleware = new AegisMCPMiddleware({
  mode: 'enforce',
  packs: ['@aegis/sql-guard', '@aegis/data-guard', '@aegis/finance-guard'],
  enableSchemaPinning: true,
  sanitizeOutputs: true,
});

// 2. Wrap an MCP Server Tool Handler
const safeExecuteSqlHandler = middleware.wrapToolHandler(
  {
    name: 'execute_sql',
    description: 'Executes a database query safely',
    inputSchema: {
      type: 'object',
      properties: { query: { type: 'string' } },
      required: ['query'],
    },
  },
  async (args) => {
    // This handler will ONLY execute if arguments pass deterministic invariants
    return await db.query(args.query);
  }
);
```

---

## 📄 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT). Copyright (c) 2026 Sneh Gabani.
