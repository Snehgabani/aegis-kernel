# 🛡️ @aegis-kernel/langchain

> **LangChain & LangGraph Deterministic Tool Safety Guard**  
> *Sub-Millisecond Invariant Clearance • Automatic Error Feedback • Safe Tool Proxying*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0-green.svg)](https://nodejs.org/)

---

## 🚀 Overview

`@aegis-kernel/langchain` wraps LangChain and LangGraph `DynamicStructuredTool` and `StructuredTool` instances with transparent, deterministic invariant clearance. If an agent attempts an unsafe action (e.g. unconstrained database deletion, parameter overflow), the guard halts execution and returns a structured invariant violation error.

---

## 📦 Installation

```bash
npm install @aegis-kernel/langchain @aegis-kernel/core
```

---

## ⚡ Quickstart

```typescript
import { DynamicStructuredTool } from '@langchain/core/tools';
import { AegisLangChainGuard } from '@aegis-kernel/langchain';
import { z } from 'zod';

// 1. Define your LangChain tools
const databaseTool = new DynamicStructuredTool({
  name: 'database_exec',
  description: 'Executes a SQL query against the database',
  schema: z.object({
    query: z.string().describe('The SQL query to execute'),
  }),
  func: async ({ query }) => {
    return await db.raw(query);
  },
});

// 2. Wrap tools with Aegis Invariant Guard
const guard = new AegisLangChainGuard({
  mode: 'enforce',
  packs: ['@aegis/sql-guard', '@aegis/data-guard'],
});

const safeTool = guard.wrap(databaseTool);
// Or wrap all agent tools in one call:
// const safeTools = guard.wrapAll([tool1, tool2, tool3]);

// 3. Pass safeTool to your LangChain AgentExecutor or LangGraph workflow
```

---

## 📄 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT). Copyright (c) 2026 Sneh Gabani.
