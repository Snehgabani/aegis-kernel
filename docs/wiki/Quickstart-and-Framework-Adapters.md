# 🚀 Quickstart & Framework Adapters

Aegis provides drop-in adapters for all major autonomous AI agent frameworks.

---

## 🦜 1. LangChain & LangGraph Integration

Wrap any LangChain `DynamicStructuredTool` or tool list with `wrapToolsWithAegis()`:

```typescript
import { wrapToolsWithAegis } from '@aegis-kernel/langchain';
import { AegisEngine } from '@aegis-kernel/core';

const aegis = new AegisEngine();
const secureTools = wrapToolsWithAegis(myTools, aegis);

// Pass secureTools to your LangGraph agent or createReactAgent
```

---

## 🤖 2. OpenAI Function Calling & Swarm

```typescript
import { AegisOpenAI } from '@aegis-kernel/openai';
import OpenAI from 'openai';

const client = new OpenAI();
const secureAegis = new AegisOpenAI({ client });

// Wrap chat completion calls to automatically intercept function arguments
const response = await secureAegis.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Transfer $50,000 to Alice' }],
  tools: myTools
});
```

---

## 🧠 3. Anthropic Claude Tool Use

```typescript
import { AegisAnthropic } from '@aegis-kernel/anthropic';
import Anthropic from '@anthropic-ai/sdk';

const anthropic = new Anthropic();
const secureAnthropic = new AegisAnthropic({ client: anthropic });

const message = await secureAnthropic.messages.create({
  model: 'claude-3-5-sonnet-20241022',
  max_tokens: 1024,
  tools: myTools,
  messages: [{ role: 'user', content: 'Query user database' }]
});
```

---

## 🔌 4. Model Context Protocol (MCP) Proxy

Protect against prompt injection and tool poisoning in external MCP servers:

```typescript
import { AegisMcpProxy } from '@aegis-kernel/mcp';

const proxy = new AegisMcpProxy({
  upstreamServer: 'http://localhost:3000/sse',
  blockPoisonedSchemas: true
});

await proxy.start({ port: 8080 });
```
