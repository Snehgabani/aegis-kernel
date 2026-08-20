# 🔬 @aegis-kernel/evals

> **Deterministic Adversarial Evaluation Harness for Academic Benchmarks & Invariant Verification**  
> *InjecAgent (ACL 2024) • AgentDojo (NeurIPS 2024) • MCP-Bench • Tricky-100 Testbed*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Adversarial Fuzz](https://img.shields.io/badge/adversarial%20fuzz-433%20vectors%2C%200%20bypasses-brightgreen.svg)](#)

---

## 🚀 Overview

`@aegis-kernel/evals` provides the standardized evaluation infrastructure and academic benchmark ingestion adapters for the Aegis Invariant Kernel:

- **InjecAgent Adapter (ACL/EMNLP 2024)**: Ingests 1,054 combinatorial test cases across Direct Harm (DH) and Data Exfiltration (DE) threat models.
- **AgentDojo Adapter (NeurIPS 2024)**: Evaluates 629 multi-domain security tasks across Banking, Workspace, Slack, and Travel domains.
- **MCPTox / MCP-Bench**: Tool poisoning, zero-width Unicode injection, and schema rug-pull detection.
- **Tricky-100 Adversarial Testbed**: 100 hand-curated boundary cases evaluating subtle evasion techniques.
- **Tree-of-Attacks (TAP) Automated Red-Teaming**: Multi-level adaptive state search exploring evasion mutations.
- **Cryptographic Double-Blind Protocol**: Sealed evaluation oracle with signed SHA-256 Merkle root verification.

---

## 📦 Installation

```bash
npm install @aegis-kernel/evals @aegis-kernel/core
```

---

## ⚡ Programmatic Usage

```typescript
import { runTricky100Testbed, evaluateDoubleBlind } from '@aegis-kernel/evals';
import { AegisEngine } from '@aegis-kernel/core';

const engine = new AegisEngine();

// 1. Run Tricky-100 Adversarial Testbed
const trickyResults = runTricky100Testbed(engine);
console.log(`Precision: ${trickyResults.precision}%, Recall: ${trickyResults.recall}%`);
console.log(`F1 Score: ${trickyResults.f1Score}%, P50 Latency: ${trickyResults.latencyP50Ms}ms`);

// 2. Run Cryptographic Double-Blind Evaluation
const blindReport = await evaluateDoubleBlind({ verbose: false });
console.log(`Merkle Root: ${blindReport.cryptographicProof.merkleRoot}`);
console.log(`Audit Signed: ${blindReport.cryptographicProof.signatureValid}`);
```

---

## 🛠️ CLI Evaluation Commands

```bash
# Run all academic benchmark suites
npx aegis eval all --output ./academic-evidence.json

# Run specific academic benchmark adapters
npx aegis eval injecagent --output ./injecagent-report.json
npx aegis eval agentdojo --output ./agentdojo-report.json
npx aegis eval mcptox --output ./mcptox-report.json

# Run with cryptographic double-blind attestation
npx aegis eval all --blinded

# Run 100-vector tricky adversarial stress testbed
npx aegis benchmark --tricky
```

## 📚 Academic References & Dataset Attribution
 
The evaluation adapters in this package evaluate against publicly published academic benchmark corpora:
 
- **InjecAgent (ACL 2024)**: Zhan et al., *InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents*, Findings of the Association for Computational Linguistics (ACL 2024). arXiv:2403.02691.
- **AgentDojo (NeurIPS 2024)**: Debenedetti et al., *AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents*, Advances in Neural Information Processing Systems (NeurIPS 2024). arXiv:2406.13314.
- **Tree-of-Attacks (TAP)**: Mehrotra et al., *Tree of Attacks: Jailbreaking Black-Box LLMs Automatically*, arXiv:2312.02119 (2023).
- **MCPTox / MCP-Bench**: Model Context Protocol security evaluation suites for tool poisoning and schema tampering.
 
---
 
## 📄 License & Attribution
 
Distributed under the [MIT License](https://opensource.org/licenses/MIT). Copyright (c) 2026 Sneh Gabani.
All benchmark adapters and dataset loaders are clean-room implementations developed for defensive evaluation and compliance under fair-use academic research standards.
