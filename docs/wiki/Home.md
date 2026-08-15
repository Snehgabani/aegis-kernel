# 🛡️ Welcome to the Aegis Invariant Kernel Wiki

The **Aegis Invariant Kernel** is an ultra-low-latency ($<1.5\text{ms}$), in-process deterministic clearance gateway and safety firewall for autonomous AI agents (LangChain, OpenAI Swarm, Anthropic Claude, LangGraph, and Model Context Protocol).

---

## 📚 Wiki Directory & Knowledge Base

### 1. 🏛️ [Architecture & Threat Model](Architecture-and-Threat-Model)
- Defense-in-depth model and 4-tier security pipeline
- Zero-Egress Core invariant and memory isolation
- AST semantic parsing vs. regex heuristic comparisons

### 2. 📜 [Invariant Specification & Rule Packs](Invariant-Specification-and-DSL)
- `aegis.config.yaml` schema definition
- Built-in rule packs: `@aegis/finance-guard`, `@aegis/sql-fortress`, `@aegis/pii-shield`
- Custom invariant checker extensions & WASM plugins

### 3. 🚀 [Quickstart & Framework Adapters](Quickstart-and-Framework-Adapters)
- Single-line integration with LangChain / LangGraph
- OpenAI Function Calling & Anthropic Tool Use interceptors
- Model Context Protocol (MCP) tool poisoning protection proxy

### 4. 🔒 [Security Controls & GRC Compliance Dossiers](Security-Controls-and-GRC-Dossiers)
- SOC2 Type II, HIPAA, ISO 27001, and EU AI Act Article 14 alignment
- Cryptographic SHA-256 Merkle audit trail chaining
- Ed25519 Biscuit token attenuation for Agent-to-Agent (A2A) delegation

### 5. 🛠️ [Operations & CLI Reference](Operations-and-CLI-Guide)
- Complete CLI commands: `init`, `test`, `scan`, `replay`, `doctor`
- Continuous performance benchmarking ($P_{95} < 5\text{ms}$)
- Docker container deployment & Multi-Cloud architectures

---

## ⚡ 60-Second Quick Example

```typescript
import { AegisEngine } from '@aegis-kernel/core';

// 1. Initialize deterministic engine with local rules
const aegis = new AegisEngine({
  rules: [
    {
      id: 'finance-cap',
      name: 'Transaction Cap',
      checker: 'numeric',
      params: { max: 10000, field: 'amount' }
    }
  ]
});

// 2. Clear tool call before agent execution
const decision = await aegis.evaluate({
  toolName: 'wire_transfer',
  parameters: { amount: 50000, recipient: '0x123...' }
});

if (!decision.allowed) {
  console.error(`🚨 BLOCKED: ${decision.reason}`);
  // Result: BLOCKED: numeric violation: amount 50000 exceeds maximum 10000
}
```
