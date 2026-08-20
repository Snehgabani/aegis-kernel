# 🏗️ Aegis — Technical Architecture Decisions

> **Why every major library and design choice was made, including alternatives considered and rejected.**

---

## 1. SQL Parsing: `node-sql-parser` over regex or custom parser

| Approach | Verdict | Rationale |
|---|---|---|
| `node-sql-parser` | **Selected** | Battle-tested (350K+ weekly downloads), multi-dialect, full AST with type information |
| Regex-only | **Rejected** | Brittle against whitespace, comment injection, nested expressions |
| Custom parser | **Rejected** | 2-3 weeks to achieve parity with `node-sql-parser` |

**Trade-off:** `node-sql-parser` occasionally fails on dialect syntax (e.g., `DELETE ... USING` in PG). The regex fallback handles this.

---

## 2. JSON Schema Validation: `ajv` over `zod` or `joi`

| Approach | Verdict | Rationale |
|---|---|---|
| `ajv` | **Selected** | Fastest validator (4-10x faster), supports JSON Schema Draft 7+ |
| `zod` | **Rejected** | No JSON Schema serialization for YAML rule packs |
| `joi` | **Rejected** | Proprietary DSL, can't generate from rule pack YAML |

---

## 3. YAML Configuration: `js-yaml` over `yaml` or `toml`

**Selected:** `js-yaml` — most widely used JS YAML library. Rejected `toml` for less human-friendly complex config.

---

## 4. Build: `tsup` + `turbo` over webpack or rollup

**Selected:** `tsup` (fast esbuild bundler) + `turbo` (monorepo orchestration). Rejected webpack (overhead), rollup (browser focus), nx (overengineered).

---

## 5. Monorepo over Multi-Repo

**Decision:** Single monorepo with npm workspaces + Turbo. Coherent versioning, single CI, simplified contributions.

---

## 6. Runtime: Node.js 18+ over Deno or Bun

**Decision:** Node.js LTS for widest ecosystem compatibility with MCP SDK, LangChain, OpenAI SDK.

---

## 7. Test Framework: Vitest over Jest

**Decision:** Vitest. Native ESM support, Jest-compatible API, TypeScript-native, faster watch mode.

---

## 8. Hash: SHA-256 over SHA-3 or BLAKE2

**Decision:** SHA-256. FIPS 140-2 compliant, hardware-accelerated, universally available across all 4 languages.

---

## 9. License: MIT over Apache 2.0 or GPL

**Decision:** MIT. Maximum adoption, compatible with all ecosystem frameworks.

---

## 10. Policy DSL: Custom AST Evaluator over OPA/Rego

**Decision:** Custom Zero-Eval Declarative Expression AST Evaluator. Eliminates runtime code execution surface. OPA/Rego WASM is roadmap item.

---

## 11. Rule Pack Format: YAML over JSON or TOML

**Decision:** YAML with JSON Schema validation on load. Human-readable, supports comments, Git-friendly diffs.

---

## 12. State Provider: Developer-Owned Interface over Built-in Storage

**Decision:** Developer-owned `StateProvider` interface. Agent cannot spoof state. Fail-closed on fetch failure.

---

## 13. Audit Log: JSONL over SQLite or stdout

**Decision:** Append-only JSONL. Simple, grep-able, pipe-able. Structured events with UUID v7 + SHA-256 proof hashes.

---

> **Last updated:** 2026-08-20 — Major changes recorded in `DECISION_JOURNAL.md`.