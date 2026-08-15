# 🛡️ Aegis AI Agent Security Linter (VS Code & Cursor)

> **In-IDE Deterministic AST Linter and Policy Verifier for AI Agent Developers**  
> *Real-Time SQL Injection Warnings • Schema Pinning Verification • Instant Feedback*

---

## ⚡ Features

- **Real-Time SQL AST Linting**: Flags unsafe tautological `WHERE 1=1` conditions and comment-evasion attempts (`DEL/**/ETE`) directly in your editor.
- **MCP Schema Validation**: Verifies that your Model Context Protocol tool schemas conform to safe parameter definitions and contain no unpinned variables.
- **Policy Pack Syntax Highlighter**: Syntax highlighting and validation for `@aegis/sql-guard`, `@aegis/data-guard`, and custom YAML policy packs.

---

## 🚀 Usage

1. Open your agent workspace in VS Code or Cursor.
2. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) and run:
   - `Aegis: Audit Agent Tool Invariants`
   - `Aegis: Verify YAML Policy Packs`
