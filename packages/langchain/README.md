# @aegis-kernel/langchain

LangChain and LangGraph deterministic tool safety guard.

## Installation

```bash
npm install @aegis-kernel/langchain @aegis-kernel/core
```

## Usage

```typescript
import { AegisLangChainGuard } from '@aegis-kernel/langchain';

const guard = new AegisLangChainGuard();
const safeTools = guard.wrapAll(myAgentTools);
```
