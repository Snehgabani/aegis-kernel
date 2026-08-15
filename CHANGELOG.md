# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-08-15

### Added
- **Core Invariant Engine (`@aegis-kernel/core`)**:
  - Deterministic AST evaluation for SQL queries (`SqlChecker`) with syntax token normalization and dialect recognition.
  - Sub-millisecond regular expression matching (`PiiChecker`) with automated Unicode NFKD homoglyph and zero-width character stripping (`\u200B`, `\uFEFF`, `\u00AD`).
  - Strict numeric bound enforcement (`NumericChecker`) supporting exponential/scientific notation coercion and nested payload recursion.
  - Stateful pre/post condition assertions (`StateChecker`) with multi-tenant session isolation (`SOC2-004`).
  - Zero-eval custom rule evaluator (`CustomChecker`) featuring strict prototype pollution immunity.
  - Self-healing recovery feedback generation with `suggestedFix` remediation payloads.
- **Enterprise Compliance Packs**:
  - Built-in rule packs for `hipaa-guard`, `pci-dss-guard`, `soc2-guard`, `eu-ai-act-guard`, `finance-guard`, `fintech-trade-guard`, `sql-guard`, and `data-guard`.
- **Framework Adapters & Ecosystem**:
  - `@aegis-kernel/mcp`: Automatic tool clearance middleware and runtime schema pinning for Model Context Protocol servers.
  - `@aegis-kernel/openai`: Stream and non-stream tool call interception for OpenAI Assistants and Chat APIs.
  - `@aegis-kernel/anthropic`: Message pre-processor and tool_use validator with structured self-healing feedback.
  - `@aegis-kernel/langchain`: Agent executor hooks and Runnable middleware.
  - `aegis-kernel` (PyPI): Python 3.9+ synchronous and async coroutine decorators (`@aegis_guard`).
- **Developer CLI (`@aegis-kernel/cli`)**:
  - Commands: `init`, `test`, `report`, `repl`, `pack list/validate`, `license activate/status`, `pricing`, and `benchmark --tricky`.
- **Evaluation & Benchmarking (`@aegis-kernel/evals`)**:
  - 100-vector adversarial benchmark testbed across 10 security domains achieving 100.0% Empirical F1 score and sub-1.5ms latency.
- **Cloud Gateway & Monetization (`@aegis-kernel/gateway`)**:
  - Hono-based Cloudflare Worker & Docker gateway with Stripe webhook subscription fulfillment and offline HMAC license token generation.
- **Enterprise Automation & Governance**:
  - Full CI/CD multi-runtime matrix (Node 18/20/22 + Python 3.9–3.12), CodeQL SAST scanning, Dependabot governance, and Git pre-commit hooks.
