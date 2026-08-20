/**
 * @file services/gateway/src/audit-store.ts
 * @description Pluggable audit-event persistence for the Aegis gateway.
 *
 * The default store remains the bounded in-memory buffer (serverless-friendly,
 * zero-config). Deployments that need durability across restarts select the
 * JSONL file store via environment:
 *
 *   AEGIS_AUDIT_STORE=jsonl
 *   AEGIS_AUDIT_PATH=/var/lib/aegis/audit.jsonl   (default: ./aegis-audit.jsonl)
 *
 * The JSONL store replays the tail of the file on boot (default window 10,000
 * events, matching the in-memory cap) so dashboard stats and paginated queries
 * survive restarts, while the full history remains on disk.
 *
 * Bring-your-own persistence (Postgres, Cloudflare D1, etc.): implement the
 * `AuditStore` interface and pass it to `createGatewayApp(_, { auditStore })`.
 * For Cloudflare D1, the recommended schema is documented in
 * `docs/enterprise/AUDIT_STORE_D1.md`.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { AegisEvent } from '@aegis-kernel/core';

export type AuditBackend = 'memory' | 'jsonl' | 'custom';

export interface AuditQueryOptions {
  limit: number;
  offset: number;
  verdict?: string;
}

export interface AuditQueryResult {
  events: AegisEvent[];
  total: number;
}

export interface AuditStore {
  readonly backend: AuditBackend;
  /** Persist events (idempotent per caller; must never throw into request path). */
  append(events: AegisEvent[]): void;
  /** Paginated, newest-first query with optional verdict filter. */
  query(options: AuditQueryOptions): AuditQueryResult;
  /** Total events currently held. */
  count(): number;
  /** Bounded window for aggregate stats. */
  all(): AegisEvent[];
}

export const AUDIT_BUFFER_CAP = 10_000;

export class InMemoryAuditStore implements AuditStore {
  readonly backend: AuditBackend = 'memory';
  private events: AegisEvent[] = [];

  public append(events: AegisEvent[]): void {
    this.events.push(...events);
    if (this.events.length > AUDIT_BUFFER_CAP) {
      this.events.splice(0, this.events.length - AUDIT_BUFFER_CAP);
    }
  }

  public query(options: AuditQueryOptions): AuditQueryResult {
    let filtered = this.events;
    if (options.verdict) {
      filtered = filtered.filter((e) => e.verdict === options.verdict);
    }
    const paginated = filtered.slice(-options.limit - options.offset, filtered.length - options.offset).reverse();
    return { events: paginated, total: filtered.length };
  }

  public count(): number {
    return this.events.length;
  }

  public all(): AegisEvent[] {
    return this.events;
  }
}

/**
 * Durable append-only JSONL store. One event per line; tail-replayed on boot.
 * Write failures are logged and swallowed by design: audit durability must
 * never take the clearance-ingestion path down (fail-open telemetry, fail-closed
 * licensing — different concerns).
 */
export class JsonlFileAuditStore implements AuditStore {
  readonly backend: AuditBackend = 'jsonl';
  private window: AegisEvent[];
  private readonly filePath: string;

  constructor(filePath: string, replayWindow: number = AUDIT_BUFFER_CAP) {
    this.filePath = path.resolve(filePath);
    this.window = [];
    this.replay(replayWindow);
  }

  private replay(windowSize: number): void {
    try {
      if (!fs.existsSync(this.filePath)) return;
      const lines = fs
        .readFileSync(this.filePath, 'utf8')
        .split('\n')
        .filter((l) => l.trim().length > 0);
      const tail = lines.slice(-windowSize);
      for (const line of tail) {
        try {
          this.window.push(JSON.parse(line) as AegisEvent);
        } catch {
          // Corrupted/interleaved line (crash mid-write): skip, keep replaying
        }
      }
    } catch (err) {
      console.warn(`[aegis-gateway] audit replay failed: ${(err as Error).message}`);
    }
  }

  public append(events: AegisEvent[]): void {
    this.window.push(...events);
    if (this.window.length > AUDIT_BUFFER_CAP) {
      this.window.splice(0, this.window.length - AUDIT_BUFFER_CAP);
    }
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.appendFileSync(
        this.filePath,
        events.map((e) => JSON.stringify(e)).join('\n') + (events.length > 0 ? '\n' : ''),
        'utf8'
      );
    } catch (err) {
      console.error(`[aegis-gateway] audit persist failed (events kept in memory): ${(err as Error).message}`);
    }
  }

  public query(options: AuditQueryOptions): AuditQueryResult {
    let filtered = this.window;
    if (options.verdict) {
      filtered = filtered.filter((e) => e.verdict === options.verdict);
    }
    const paginated = filtered.slice(-options.limit - options.offset, filtered.length - options.offset).reverse();
    return { events: paginated, total: filtered.length };
  }

  public count(): number {
    return this.window.length;
  }

  public all(): AegisEvent[] {
    return this.window;
  }
}

export function createAuditStoreFromEnv(env?: {
  AEGIS_AUDIT_STORE?: string;
  AEGIS_AUDIT_PATH?: string;
}): AuditStore {
  const kind = env?.AEGIS_AUDIT_STORE || process.env.AEGIS_AUDIT_STORE;
  if (kind === 'jsonl') {
    const p = env?.AEGIS_AUDIT_PATH || process.env.AEGIS_AUDIT_PATH || './aegis-audit.jsonl';
    return new JsonlFileAuditStore(p);
  }
  return new InMemoryAuditStore();
}
