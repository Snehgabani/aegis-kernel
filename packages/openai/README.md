# 🛡️ @aegis-kernel/openai

> **OpenAI Function Calling & Assistant Tools Deterministic Safety Guard**  
> *Pre-Execution Clearance • Structured Self-Healing Error Feedback • Tool Message Interception*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0-green.svg)](https://nodejs.org/)

---

## 🚀 Overview

`@aegis-kernel/openai` intercepts OpenAI chat completion tool calls (`message.tool_calls`) and enforces deterministic policy invariants before dispatching tool execution. If a tool call violates an invariant, the guard automatically synthesizes a self-healing tool error message that guides the LLM to auto-correct its arguments.

---

## 📦 Installation

```bash
npm install @aegis-kernel/openai @aegis-kernel/core
```

---

## ⚡ Quickstart

```typescript
import OpenAI from 'openai';
import { AegisOpenAIGuard } from '@aegis-kernel/openai';

const openai = new OpenAI();
const guard = new AegisOpenAIGuard({
  mode: 'enforce',
  packs: ['@aegis/sql-guard', '@aegis/finance-guard'],
});

const completion = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Clean up inactive users table' }],
  tools: myToolDefinitions,
});

const message = completion.choices[0].message;

if (message.tool_calls) {
  for (const toolCall of message.tool_calls) {
    // Automatically intercepts, validates invariants, and executes safely
    const toolMessage = await guard.handleToolCall(toolCall, async (args) => {
      return await myLocalToolExecutor(args);
    });

    // toolMessage contains either the execution output or structured self-healing feedback
    messages.push(toolMessage);
  }
}
```

---

## 📄 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT). Copyright (c) 2026 Sneh Gabani.
