# @aegis-kernel/openai

OpenAI Function Calling and Assistant Tools deterministic safety guard.

## Installation

```bash
npm install @aegis-kernel/openai @aegis-kernel/core
```

## Usage

```typescript
import { AegisOpenAIGuard } from '@aegis-kernel/openai';

const guard = new AegisOpenAIGuard();

for (const toolCall of completion.choices[0].message.tool_calls) {
  const toolMessage = await guard.handleToolCall(toolCall, async (args) => {
    return executeTool(args);
  });
  messages.push(toolMessage);
}
```
