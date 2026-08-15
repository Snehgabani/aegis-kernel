# @aegis-kernel/core

The core deterministic invariant clearance engine for AI agent tool calls.

## Installation

```bash
npm install @aegis-kernel/core
```

## Basic Usage

```typescript
import { AegisEngine } from '@aegis-kernel/core';

const engine = new AegisEngine({
  mode: 'enforce', // or 'shadow'
  failPolicy: 'fail-open',
});

const verdict = engine.evaluate({
  tool: 'database_query',
  params: { sql: 'DELETE FROM accounts WHERE id = 123;' },
});

console.log(verdict.allowed); // true
```
