# GitHub Copilot & GitHub Agents Repository Instructions

Welcome, GitHub Agent! This document defines the architectural rules, coding standards, and invariant requirements for the **Aegis Invariant Kernel** repository.

---

## 🛡️ Core Mission & Architectural Invariants

Aegis is an ultra-fast, in-process deterministic tool-call clearance gateway for autonomous AI agents.

### ⚠️ Non-Negotiable Invariants
1. **Zero Network Egress in Core**:
   - `@aegis-kernel/core` MUST NOT make outbound network requests by default.
   - All AST parsing, regular expressions, cryptographic HMAC proofs, and numeric checks must run entirely locally and deterministically in-process.
2. **Sub-1.5ms Latency Budget**:
   - $P_{50} < 0.5\text{ms}$ and $P_{95} < 5\text{ms}$ across all validator checkers.
   - Do NOT introduce blocking I/O, heavy sync sleep, or polynomial ReDoS regexes.
3. **Deterministic AST State Machine**:
   - SQL queries are evaluated via AST node analysis and single-pass linear state machines. Never use polynomial backtracking regular expressions (`/[\s\S]*?/`).

---

## 🏗️ Monorepo Structure

```
packages/
├── core/         # Core evaluation engine, AST checkers, HMAC proofs, GRC dossiers
├── cli/          # 'aegis' CLI tool (init, test, scan, replay, doctor, triage)
├── mcp/          # Model Context Protocol security scanner & proxy
├── langchain/    # LangChain / LangGraph middleware adapter
├── openai/       # OpenAI SDK & Assistants tool call wrapper
├── anthropic/    # Anthropic Claude SDK tool call wrapper
├── evals/        # Adversarial benchmarks (50-vector seed, 100-vector tricky testbed)
├── diagnostics/  # Full subsystem health checker and upgrade auditor
├── python/       # Native Python SDK (`pip install aegis-kernel`)
└── go/           # Native Go bindings (`go get github.com/snehgabani/aegis-kernel/packages/go`)

services/
├── control-plane/# Central policy distribution & tenant telemetry service
└── gateway/      # Standalone HTTP/REST & WebSocket clearance proxy (Hono / Node 22)
```

---

## 🔧 Build, Test & Verification Commands

When writing or modifying code, ALWAYS verify your changes using these commands:

```bash
# Install dependencies
npm ci

# Build all monorepo packages (via Turborepo)
npm run build

# Run all 47 test suites (266+ tests)
npm run test

# Run code linter
npm run lint

# Run diagnostic verification
npx aegis doctor

# Run full live operational proof across all 25 subsystems
node scripts/live-e2e-proof.mjs
```

---

## 📝 Coding Style & Conventions

- **TypeScript**: Strict mode enabled (`tsconfig.json`). Always specify explicit types for function parameters and return values.
- **ES Modules**: All JavaScript/TypeScript files in `packages/` use ESM (`"type": "module"`).
- **Line Endings**: LF only (`.editorconfig`, `.gitattributes`).
- **Conventional Commits**: Format commit messages as `feat(scope): ...`, `fix(scope): ...`, `docs(scope): ...`.
