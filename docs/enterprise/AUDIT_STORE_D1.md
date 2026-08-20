# Gateway Audit Store — Deployment Guide

The gateway's audit-event persistence is pluggable (`services/gateway/src/audit-store.ts`).

| Backend | Selection | Durability | Use case |
|---|---|---|---|
| `memory` (default) | no configuration | process lifetime | demos, tests, serverless with external sink |
| `jsonl` | `AEGIS_AUDIT_STORE=jsonl` (+ `AEGIS_AUDIT_PATH`) | append-only file, tail-replayed on boot | single-node / container with a volume |
| custom | `createGatewayApp(env, { auditStore })` | yours | Postgres / ClickHouse / etc. |

## JSONL (durable single-node)

```bash
AEGIS_AUDIT_STORE=jsonl \
AEGIS_AUDIT_PATH=/var/lib/aegis/audit.jsonl \
npm start
```

Behavior: one event per line; the last 10,000 events are replayed on boot so
`/api/dashboard/*` and `/health/deep` survive restarts; the full history stays on
disk for `aegis replay`. Persist failures degrade to memory-only and log —
ingestion never fails because of the audit sink.

## Cloudflare D1 (reference schema + adapter sketch)

Implement `AuditStore` and bind a D1 database:

```sql
CREATE TABLE IF NOT EXISTS aegis_audit_events (
  id            TEXT PRIMARY KEY,          -- event UUIDv7
  ts            TEXT NOT NULL,             -- ISO 8601
  framework     TEXT NOT NULL,
  tool_name     TEXT NOT NULL,
  fingerprint   TEXT NOT NULL,
  mode          TEXT NOT NULL,
  verdict       TEXT NOT NULL,             -- ALLOWED | BLOCKED
  rules_fired   TEXT NOT NULL,             -- JSON array
  latency_ms    REAL NOT NULL,
  proof_hash    TEXT NOT NULL,             -- Merkle leaf commitment
  policy_hash   TEXT NOT NULL,
  raw           TEXT NOT NULL              -- full event JSON
);
CREATE INDEX IF NOT EXISTS idx_aegis_verdict_ts ON aegis_audit_events (verdict, ts DESC);
CREATE INDEX IF NOT EXISTS idx_aegis_tool_ts ON aegis_audit_events (tool_name, ts DESC);
```

```ts
import type { AuditStore } from './audit-store.js';

export class D1AuditStore implements AuditStore {
  readonly backend = 'custom' as const;
  constructor(private db: D1Database) {}
  async append(events) {
    const stmt = this.db.prepare(
      'INSERT INTO aegis_audit_events (id, ts, framework, tool_name, fingerprint, mode, verdict, rules_fired, latency_ms, proof_hash, policy_hash, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
    );
    await this.db.batch(events.map((e) => stmt.bind(e.id, e.timestamp, e.framework, e.toolName, e.toolCallFingerprint, e.mode, e.verdict, JSON.stringify(e.rulesFired), e.latencyMs, e.proofHash, e.policyCommitmentHash, JSON.stringify(e))));
  }
  // query/count/all: SELECT with ORDER BY ts DESC LIMIT ? OFFSET ?
}
```

Retention: D1 `events` can be rotated with a scheduled Worker
(`DELETE ... WHERE ts < datetime('now', '-180 days')`); EU AI Act Article 12
expects logs appropriate to the system's expected lifetime — for high-risk
deployments target at least 6 months (align with your classification analysis).
