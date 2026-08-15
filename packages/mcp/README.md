# @aegis-kernel/mcp

Model Context Protocol (MCP) JSON-RPC 2.0 safety clearance middleware.

## Installation

```bash
npm install @aegis-kernel/mcp @aegis-kernel/core
```

## Usage

```typescript
import { AegisMCPMiddleware } from '@aegis-kernel/mcp';

const middleware = new AegisMCPMiddleware();

// Wrap an MCP Server handler
const safeQueryHandler = middleware.wrapToolHandler(
  'execute_sql',
  async (args) => {
    return await db.query(args.sql);
  }
);
```
