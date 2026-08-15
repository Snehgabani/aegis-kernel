# 🛠️ Operations & CLI Reference Guide

The `@aegis-kernel/cli` (`aegis`) binary provides shift-left security scanning, live diagnostics, replay verification, and rule initialization.

---

## 💻 CLI Commands

### 1. Initialize Aegis in Workspace
```bash
npx aegis init
```
Generates `aegis.config.yaml` and sets up the local `.aegis/` state directory.

### 2. Shift-Left Threat & Invariant Scanner
```bash
npx aegis scan ./src
```
Scans agent source code and JSON tool definitions for:
- Hardcoded API tokens and secret leaks
- Poisoned MCP tool schemas (invisible zero-width unicode, homoglyphs)
- Dangerous un-sandboxed `eval` or command execution calls

### 3. Deterministic Audit Replay Engine
```bash
npx aegis replay .aegis/audit-log.json
```
Replays historical production tool calls against updated policies to detect regressions or policy drift.

### 4. Deep System Diagnostics
```bash
npx aegis doctor
```
Executes a 9-point subsystem verification audit across all checker modules and reports health status.
