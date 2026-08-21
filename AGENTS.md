# AGENTS.md — Instructions for AI Coding Agents

This file provides context for AI coding agents (Claude Code, Cursor, Copilot, Windsurf) working with the Aegis Invariant Kernel codebase.

## Project structure

```
aegis-kernel/
├── packages/
│   ├── core/              # TypeScript invariant engine (main library)
│   ├── mcp/               # Model Context Protocol middleware
│   ├── langchain/         # LangChain / CrewAI / AutoGen adapter
│   ├── openai/            # OpenAI SDK tool call interceptor
│   ├── anthropic/         # Claude tool use guard
│   ├── vercel-ai/         # Vercel AI SDK Core middleware
│   ├── cli/               # CLI tool (aegis init, eval, scan, etc.)
│   ├── diagnostics/       # Forensic tracer & shadow tool discovery
│   ├── evals/             # Academic benchmark evaluation suite
│   ├── python/            # Python SDK (zero dependencies)
│   ├── go/                # Go SDK
│   └── rust/              # Rust crate
├── examples/              # Reference architectures (CrewAI, LangGraph, FastAPI, etc.)
├── services/              # Supporting services (gateway, control-plane)
├── site/                  # GitHub Pages (playground, docs, dashboard)
├── scripts/               # Build and verification scripts
└── docs/                  # Technical documentation, compliance, research
```

## Build and test

```bash
npm install            # install all workspace dependencies
npm run build          # build all TypeScript packages (tsup)
npm test               # run all 674 tests across 90 suites (vitest)
npm run lint           # ESLint / Turbo lint across all packages
```

Python tests:
```bash
cd packages/python && python -m unittest discover tests
```

Go tests:
```bash
cd packages/go && go test -v ./...
```

Rust tests:
```bash
cd packages/rust && cargo test
```

## Key conventions

- **Monorepo**: Uses npm workspaces + Turborepo for orchestration
- **Module format**: ESM (`"type": "module"` in package.json)
- **TypeScript**: Strict mode, compiled with tsup
- **Testing**: Vitest for TypeScript, unittest for Python, `go test` for Go, `cargo test` for Rust
- **Node.js**: Requires >=18.0 (20.x, 22.x LTS validated)
- **Python**: Requires >=3.9 (3.10, 3.11, 3.12 validated), zero external dependencies

## How to use Aegis in user code

### TypeScript — protect a tool call
```typescript
import { AegisEngine } from '@aegis-kernel/core';

const engine = new AegisEngine({ mode: 'enforce' });
const result = engine.evaluate({
  tool: 'database_query',
  params: { query: 'SELECT * FROM users WHERE id = 1' }
});
// result.verdict: 'ALLOWED' | 'BLOCKED' | 'REASK'
```

### Python — decorator pattern
```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="database_exec")
def run_query(query: str):
    return db.execute(query)
```

### MCP middleware
```typescript
import { AegisMCPMiddleware } from '@aegis-kernel/mcp';

const middleware = new AegisMCPMiddleware({
  mode: 'enforce',
  packs: ['@aegis/sql-guard', '@aegis/data-guard']
});
const safeHandler = middleware.wrapToolHandler('database_query', handler);
```

## Package imports

| Package | npm / registry name | Main export |
|:---|:---|:---|
| Core engine | `@aegis-kernel/core` | `AegisEngine`, `AegisStreamInterceptor`, `ConversationTracker`, `ExecutionDAG`, `PolicyEngine` |
| MCP middleware | `@aegis-kernel/mcp` | `AegisMCPMiddleware` |
| LangChain adapter | `@aegis-kernel/langchain` | `AegisLangChainGuard` |
| OpenAI adapter | `@aegis-kernel/openai` | `AegisOpenAIGuard` |
| Anthropic adapter | `@aegis-kernel/anthropic` | `AegisAnthropicGuard` |
| Vercel AI adapter | `@aegis-kernel/vercel-ai` | `createAegisMiddleware` |
| CLI | `@aegis-kernel/cli` | CLI binary (`npx aegis`) |
| Python SDK | `aegis-kernel` (PyPI) | `aegis_guard` decorator, `PythonStateChecker`, `PythonPiiTokenVault` |

## Common tasks

- **Add a new invariant check**: Implement in `packages/core/src/`, add tests in `packages/core/__tests__/`
- **Add a new CLI command**: Add to `packages/cli/src/`
- **Add a benchmark**: Add dataset to `packages/evals/src/benchmarks/`
- **Modify policy DSL**: Core logic in `packages/core/src/policy/`
- **Update documentation site**: Edit files in `site/`
