import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createGatewayApp } from '../src/index.js';
import {
  InMemoryAuditStore,
  JsonlFileAuditStore,
  createAuditStoreFromEnv,
  AUDIT_BUFFER_CAP,
  type AegisEvent,
} from '../src/audit-store.js';
import type { AegisEvent as CoreEvent } from '@aegis-kernel/core';

let tmp: string;

function sampleEvent(id: string, verdict: 'ALLOWED' | 'BLOCKED' = 'BLOCKED'): AegisEvent {
  return {
    id,
    timestamp: new Date().toISOString(),
    version: '1.0.1',
    framework: 'openai',
    toolName: 'execute_sql',
    toolCallFingerprint: `fp_${id}`,
    mode: 'enforce',
    verdict,
    rulesEvaluated: 6,
    rulesFired: verdict === 'BLOCKED' ? [{ ruleId: 'SQL-001', packId: '@aegis/sql-guard', severity: 'critical', message: 'DROP', suggestedFix: 'reject' }] : [],
    latencyMs: 0.42,
    proofHash: `proof_${id}`,
    policyCommitmentHash: 'pc',
    userOverride: false,
  } as unknown as AegisEvent;
}

describe('InMemoryAuditStore (default — behavior preserved)', () => {
  it('caps the buffer at 10,000 events (bounded for serverless runtimes)', () => {
    const store = new InMemoryAuditStore();
    const batch = Array.from({ length: 500 }, (_, i) => sampleEvent(`e${i}`));
    for (let i = 0; i < 21; i++) store.append(batch); // 10,500 events
    expect(store.count()).toBe(AUDIT_BUFFER_CAP);
  });

  it('query: newest-first pagination + verdict filter', () => {
    const store = new InMemoryAuditStore();
    store.append([sampleEvent('a1', 'ALLOWED'), sampleEvent('a2'), sampleEvent('a3', 'ALLOWED')]);
    const all = store.query({ limit: 10, offset: 0 });
    expect(all.total).toBe(3);
    expect(all.events[0].id).toBe('a3'); // newest first
    const blockedOnly = store.query({ limit: 10, offset: 0, verdict: 'BLOCKED' });
    expect(blockedOnly.total).toBe(1);
    expect(blockedOnly.events[0].id).toBe('a2');
  });
});

describe('JsonlFileAuditStore (durable persistence)', () => {
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-audit-'));
  });
  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('persists events to disk as JSONL and replays them in a NEW store instance (restart survival)', () => {
    const file = path.join(tmp, 'audit.jsonl');
    const storeA = new JsonlFileAuditStore(file);
    storeA.append([sampleEvent('p1'), sampleEvent('p2', 'ALLOWED')]);

    const raw = fs.readFileSync(file, 'utf8');
    expect(raw.split('\n').filter((l) => l.trim())).toHaveLength(2);
    expect(raw).toContain('"id":"p1"');

    // Simulate process restart: fresh store over the same file
    const storeB = new JsonlFileAuditStore(file);
    expect(storeB.count()).toBe(2);
    const q = storeB.query({ limit: 10, offset: 0, verdict: 'BLOCKED' });
    expect(q.total).toBe(1);
    expect(q.events[0].id).toBe('p1');
  });

  it('skips corrupted trailing lines during replay (crash mid-write tolerance)', () => {
    const file = path.join(tmp, 'audit.jsonl');
    fs.writeFileSync(file, JSON.stringify(sampleEvent('ok1')) + '\n{"id":"trunc', 'utf8');
    const store = new JsonlFileAuditStore(file);
    expect(store.count()).toBe(1);
  });

  it('events survive gateway restarts end-to-end via env configuration', async () => {
    const file = path.join(tmp, 'gateway-audit.jsonl');
    const store = createAuditStoreFromEnv({ AEGIS_AUDIT_STORE: 'jsonl', AEGIS_AUDIT_PATH: file });
    const app = createGatewayApp(
      { AEGIS_LICENSE_SECRET: 's', STRIPE_WEBHOOK_SECRET: 'w' },
      { auditStore: store }
    );
    const res = await app.request('/api/telemetry', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer test' },
      body: JSON.stringify({ events: [sampleEvent('gw1'), sampleEvent('gw2', 'ALLOWED')] }),
    });
    expect(res.status).toBe(200);

    // New app instance (restart) with a store over the same file: events persist
    const store2 = new JsonlFileAuditStore(file);
    const app2 = createGatewayApp(
      { AEGIS_LICENSE_SECRET: 's', STRIPE_WEBHOOK_SECRET: 'w' },
      { auditStore: store2 }
    );
    const stats = await (await app2.request('/api/dashboard/stats')).json();
    expect(stats.totalChecks).toBe(2);
    expect(stats.totalBlocked).toBe(1);
    const events = await (await app2.request('/api/dashboard/events?limit=10')).json();
    expect(events.total).toBe(2);
    expect(events.events[0].id).toBe('gw2'); // newest first
  });

  it('write failures degrade to memory-only (ingestion never 500s)', () => {
    const store = new JsonlFileAuditStore(path.join(tmp, 'ok.jsonl'));
    store.append([sampleEvent('before')]);
    // Subsequent append to an UNWRITABLE path: constructor path fixed, so test via
    // a store pointed at a path whose parent is a FILE (mkdir fails)
    const bad = new JsonlFileAuditStore(path.join(tmp, 'ok.jsonl', 'nested', 'audit.jsonl'));
    expect(() => bad.append([sampleEvent('x')])).not.toThrow();
    expect(bad.count()).toBe(1); // retained in memory window despite persist failure
  });
});

describe('createAuditStoreFromEnv', () => {
  it('defaults to in-memory; jsonl env selects durable store', () => {
    expect(createAuditStoreFromEnv().backend).toBe('memory');
    expect(createAuditStoreFromEnv({ AEGIS_AUDIT_STORE: 'jsonl' }).backend).toBe('jsonl');
  });
});
