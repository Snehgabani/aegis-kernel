# 🛡️ @aegis-kernel/diagnostics

> **Diagnostic Health, Runtime Integrity & Subsystem Probing Engine for Aegis Invariant Kernel**  
> *Deterministic Zero-Egress Health Audits • Subsystem Probes • System Telemetry*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0-green.svg)](https://nodejs.org/)

---

## 🚀 Overview

`@aegis-kernel/diagnostics` provides programmatic health checks and runtime integrity validation across all Aegis Invariant Kernel subsystems:

- **Core Engine Verification**: Instantiation, baseline evaluation, and rule pack readiness.
- **Multi-Dialect SQL Checker**: AST mutation blocking, DDL filtering, and tautology detection.
- **Salted PII & Secret Vault**: Tokenization/detokenization roundtrips and zero-egress pattern scanning.
- **Numeric & Financial Bounds**: Currency string stripping and parameter alias enforcement.
- **RBAC & Identity System**: Monotonic Ed25519 Biscuit token attenuation and permission gates.
- **Enterprise Entitlements & License**: Plan verification and HMAC license checking.
- **Streaming & MCP Security**: Sliding window token interception and tool schema drift detection.

---

## 📦 Installation

```bash
npm install @aegis-kernel/diagnostics @aegis-kernel/core
```

---

## ⚡ Programmatic Usage

```typescript
import { AegisDiagnostics } from '@aegis-kernel/diagnostics';

const diagnostics = new AegisDiagnostics();
const report = await diagnostics.runFullDiagnostics();

console.log(`System Status: ${report.overallStatus}`);
console.log(`Checks Passed: ${report.summary.passed}/${report.checks.length}`);

for (const check of report.checks) {
  console.log(`[${check.status}] ${check.name} (${check.durationMs}ms): ${check.message}`);
}
```

---

## 🛠️ CLI Diagnostics

Run health checks directly from the command line:

```bash
npx aegis doctor
```

---

## 📄 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT). Copyright (c) 2026 Sneh Gabani.
