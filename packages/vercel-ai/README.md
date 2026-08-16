# 🛡️ Aegis Invariant Kernel for Vercel AI SDK

> **Deterministic Tool-Call Safety Gateway for Vercel AI SDK Core & Next.js Agents**  
> *Sub-Millisecond Clearance • Zero Network Egress • Self-Healing Feedback*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![npm version](https://img.shields.io/badge/npm-v1.0.0-blue.svg)](https://www.npmjs.com/package/@aegis-kernel/vercel-ai)
[![Tests](https://img.shields.io/badge/tests-4%2F4%20passing-brightgreen.svg)](#)

---

## 🚀 Installation

```bash
npm install @aegis-kernel/vercel-ai @aegis-kernel/core
```

---

## ⚡ Quickstart

### 1-Line Tool Protection with `wrapVercelTool`

```typescript
import { tool } from 'ai';
import { z } from 'zod';
import { wrapVercelTool } from '@aegis-kernel/vercel-ai';

// Define your standard Vercel AI SDK tool
export const dbTool = wrapVercelTool(
  'database_exec',
  tool({
    description: 'Execute database queries on PostgreSQL',
    parameters: z.object({
      query: z.string().describe('The SQL query to execute'),
    }),
    execute: async ({ query }) => {
      // Aegis guarantees this only executes if SQL invariants pass!
      // Destructive queries (DROP TABLE, DELETE without WHERE, etc.) are blocked.
      return await db.query(query);
    },
  })
);
```

---

## 🧪 Running Tests

```bash
npm test -- vercel-ai.test.ts
```
