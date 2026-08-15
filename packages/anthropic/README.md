# @aegis-kernel/anthropic

Anthropic Claude `tool_use` safety clearance guard with structured reflection.

## Installation

```bash
npm install @aegis-kernel/anthropic @aegis-kernel/core
```

## Usage

```typescript
import { AegisAnthropicGuard } from '@aegis-kernel/anthropic';

const guard = new AegisAnthropicGuard();

const resultBlock = await guard.handleToolUse(contentBlock, async (input) => {
  return await myExecutor(input);
});
```
