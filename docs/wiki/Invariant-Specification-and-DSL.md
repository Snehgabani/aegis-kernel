# 📜 Invariant Specification & Configuration DSL

Aegis policies are defined in YAML via `aegis.config.yaml` or programmatically in TypeScript/Python.

---

## ⚙️ `aegis.config.yaml` Example

```yaml
version: "1.0.0"
mode: "enforce" # 'enforce' (block violations) | 'audit' (log-only)

rules:
  # Rule 1: Financial Wire Cap
  - id: "finance-max-transfer"
    name: "Maximum Wire Transfer Cap"
    checker: "numeric"
    severity: "CRITICAL"
    tools: ["transfer_funds", "wire_money", "payout"]
    params:
      field: "amount"
      min: 0
      max: 10000

  # Rule 2: SQL Drop / Truncate Prevention
  - id: "sql-drop-table-guard"
    name: "Block Destructive SQL Mutations"
    checker: "sql"
    severity: "CRITICAL"
    tools: ["execute_sql", "query_database"]
    params:
      disallowedStatements: ["DROP", "TRUNCATE", "ALTER"]
      requireWhereClauseOnDelete: true

  # Rule 3: PII Redaction
  - id: "pii-sanitization-guard"
    name: "Redact Sensitive PII"
    checker: "pii"
    severity: "HIGH"
    tools: ["*"]
    params:
      redactFields: ["ssn", "credit_card", "email", "phone"]
      maskingStrategy: "tokenize" # 'mask' | 'tokenize' | 'hash'
```

---

## 📦 Built-In Rule Packs

Aegis ships with pre-configured, battle-tested rule packs:
- `@aegis/finance-guard`: Enforces transaction maximums, slippage limits, negative balance protection.
- `@aegis/sql-fortress`: Prohibits unindexed full-table updates, drop/truncate queries, and hex-encoded SQL injections.
- `@aegis/pii-shield`: Detects and tokenizes SSNs, credit cards, emails, and IBAN numbers.
- `@aegis/mcp-sentinel`: Scans tool descriptions for invisible zero-width unicode, homoglyphs, and prompt injection sequences.
