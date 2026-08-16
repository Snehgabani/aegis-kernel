# 🛡️ @aegis-kernel/anthropic

> **Anthropic Claude Tool-Use Deterministic Safety Clearance Guard**  
> *Pre-Execution Clearance • Claude `tool_use` / `tool_result` Interception • Structured Self-Healing Feedback*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0-green.svg)](https://nodejs.org/)

---

## 🚀 Overview

`@aegis-kernel/anthropic` intercepts Anthropic Claude `tool_use` content blocks and evaluates deterministic security invariants before tool execution occurs. If a tool call violates a policy invariant, it constructs a standardized `tool_result` error block containing actionable self-healing guidance for Claude to re-ask safely.

---

## 📦 Installation

```bash
npm install @aegis-kernel/anthropic @aegis-kernel/core
```

---

## ⚡ Quickstart

```typescript
import Anthropic from '@anthropic-ai/sdk';
import { AegisAnthropicGuard } from '@aegis-kernel/anthropic';

const anthropic = new Anthropic();
const guard = new AegisAnthropicGuard({
  mode: 'enforce',
  packs: ['@aegis/sql-guard', '@aegis/data-guard'],
});

const response = await anthropic.messages.create({
  model: 'claude-3-5-sonnet-20241022',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'Delete records older than 30 days' }],
  tools: myClaudeTools,
});

for (const content of response.content) {
  if (content.type === 'tool_use') {
    // Intercept, evaluate invariants, and execute
    const resultBlock = await guard.handleToolUse(content, async (input) => {
      return await executeMyTool(content.name, input);
    });

    // Feed resultBlock back to Claude in next turn
    nextTurnMessages.push({ role: 'user', content: [resultBlock] });
  }
}
```

---

## 📄 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT). Copyright (c) 2026 Sneh Gabani.
