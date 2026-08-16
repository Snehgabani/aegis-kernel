# 🛡️ @aegis-kernel/cli

> **Developer CLI & Shift-Left Invariant Auditing Tool for Aegis Invariant Kernel**  
> *Academic Benchmark Runner • Invariant Scanner • Compliance Dossier Verification • Live REPL*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0-green.svg)](https://nodejs.org/)

---

## 📦 Installation

```bash
# Global installation
npm install -g @aegis-kernel/cli

# Or run directly via npx
npx aegis --help
```

---

## 🛠️ CLI Commands & Usage

### 1. Workspace & Diagnostic Commands

```bash
# Initialize aegis.config.yaml and local .aegis/ directory
npx aegis init

# Run system health diagnostics across all invariant subsystems
npx aegis doctor

# Scan workspace files, prompts, and MCP schemas for secrets & prompt injection
npx aegis scan .
```

### 2. Testing & Academic Benchmarks

```bash
# Run security bounds testbed & compute Agent Safety Scorecard
npx aegis test

# Run standardized academic evaluation suites (InjecAgent, AgentDojo, MCPTox)
npx aegis eval all --output ./academic-evidence.json

# Run academic evaluation with cryptographic double-blind attestation
npx aegis eval all --blinded

# Run 100-vector tricky adversarial stress testbed
npx aegis benchmark --tricky
```

### 3. Compliance & GRC Audit Verification

```bash
# Export audit-ready compliance dossier (SOC 2, ISO 42001, EU AI Act, HIPAA)
npx aegis compliance export --format markdown --output ./compliance-dossier.md

# Cryptographically verify Merkle root chains and signatures in an audit dossier
npx aegis verify-proof ./compliance-dossier.json --key "signing-key"

# Display threat coverage matrix mapped to OWASP GenAI Top 10 (2026) & MITRE ATLAS
npx aegis matrix
```

### 4. Interactive & Rule Pack Management

```bash
# Interactive terminal REPL for live tool clearance evaluation
npx aegis repl

# Deterministically replay historical audit logs against active policy rules
npx aegis replay ./audit-log.json

# Discover, install, and validate invariant rule packs
npx aegis pack list
npx aegis pack validate ./my-pack.yaml
npx aegis hub list
```

---

## 📄 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT). Copyright (c) 2026 Sneh Gabani.
