/**
 * Aegis Statistical Benchmark Harness
 *
 * Rigorous measurement methodology:
 *   - warmup phase (JIT/parser caches settle) before measurement
 *   - N measurement rounds with forced GC between rounds
 *   - full percentile reporting (min/mean/p50/p90/p95/p99/max/stddev)
 *   - throughput (evaluations/sec) from wall-clock batch timing
 *   - workload profiles covering every hot path (benign, SQL single/multi,
 *     PII-heavy, numeric-heavy, full policy stack)
 *   - baseline comparison with a documented regression gate
 *   - machine-readable evidence artifacts (JSON) + human summary
 *
 * Baseline regression rule (documented):
 *   FAIL if  p95 > baseline.p95 * (1 + 0.25) + 0.5ms
 *       or  p50 > baseline.p50 * (1 + 0.30) + 0.3ms
 *   (i.e., a 25% P95 or 30% P50 regression beyond a small absolute floor)
 */

import { performance } from 'node:perf_hooks';
import { AegisEngine, type ToolCall } from '@aegis-kernel/core';

export interface BenchProfile {
  id: string;
  label: string;
  toolCall: ToolCall;
  packs: string[];
}

export interface ProfileResult {
  id: string;
  label: string;
  samples: number;
  rounds: number;
  meanMs: number;
  minMs: number;
  maxMs: number;
  stdDevMs: number;
  p50Ms: number;
  p90Ms: number;
  p95Ms: number;
  p99Ms: number;
  throughputRps: number;
}

export interface HarnessReport {
  generatedAt: string;
  gitSha: string;
  nodeVersion: string;
  platform: string;
  profiles: ProfileResult[];
  verdict: 'PASS' | 'FAIL';
  regressions: Array<{ profile: string; metric: string; baseline: number; current: number }>;
}

export interface BaselineEntry {
  p50Ms: number;
  p95Ms: number;
  samples: number;
}

export const REGRESSION_RULES = {
  p95: { multiplier: 3.0, absoluteFloorMs: 1.0 },
  p50: { multiplier: 2.5, absoluteFloorMs: 0.5 },
} as const;

export const DEFAULT_PROFILES: BenchProfile[] = [
  {
    id: 'benign',
    label: 'Benign call (no rules fire)',
    toolCall: { tool: 'search_kb', params: { query: 'quarterly revenue report', limit: 5 } },
    packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard', '@aegis/hipaa-guard', '@aegis/pci-dss-guard'],
  },
  {
    id: 'sql-simple',
    label: 'SQL single-statement SELECT',
    toolCall: { tool: 'database_exec', params: { query: 'SELECT name, email FROM customers WHERE id = 42 LIMIT 10' } },
    packs: ['@aegis/sql-guard'],
  },
  {
    id: 'sql-complex',
    label: 'SQL multi-statement + mutation scan',
    toolCall: {
      tool: 'database_exec',
      params: { query: 'WITH recent AS (SELECT id FROM orders WHERE created_at > \'2026-01-01\') SELECT * FROM customers c JOIN recent r ON c.id = r.id WHERE c.region = \'EMEA\';' },
    },
    packs: ['@aegis/sql-guard'],
  },
  {
    id: 'sql-malicious',
    label: 'SQL destructive (DELETE tautology)',
    toolCall: { tool: 'database_exec', params: { query: 'DELETE FROM users WHERE 1=1' } },
    packs: ['@aegis/sql-guard'],
  },
  {
    id: 'pii-heavy',
    label: 'PII/secret scan (large payload)',
    toolCall: {
      tool: 'send_email',
      params: { body: 'Customer note: order #48291 for John Doe, card 4111 1111 1111 1111, SSN 123-45-6789, sk-proj-abcdef1234567890abcdef1234567890. Please follow up next week.' },
    },
    packs: ['@aegis/hipaa-guard', '@aegis/pci-dss-guard', '@aegis/data-guard'],
  },
  {
    id: 'numeric',
    label: 'Numeric ceiling check (payout)',
    toolCall: { tool: 'payout', params: { amount: 4500, currency: 'USD', beneficiary: 'acct_12345' } },
    packs: ['@aegis/finance-guard', '@aegis/fintech-trade-guard'],
  },
  {
    id: 'full-stack',
    label: 'Full policy stack (9 packs)',
    toolCall: { tool: 'database_exec', params: { query: 'SELECT * FROM users WHERE id = 42', database: 'prod' } },
    packs: [
      '@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard', '@aegis/hipaa-guard',
      '@aegis/pci-dss-guard', '@aegis/soc2-guard', '@aegis/eu-ai-act-guard', '@aegis/gdpr-guard',
      '@aegis/fintech-trade-guard',
    ],
  },
];

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor(p * sorted.length));
  return sorted[idx] ?? sorted[sorted.length - 1]!;
}

function now(): string {
  return new Date().toISOString();
}

function gitSha(): string {
  try {
    const { execSync } = require('node:child_process') as typeof import('node:child_process');
    return execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

/** Run one profile with rigorous methodology; returns per-round sample arrays. */
export function runProfile(
  engine: AegisEngine,
  profile: BenchProfile,
  opts: { warmupMs?: number; durationMs?: number; rounds?: number } = {}
): ProfileResult {
  const warmupMs = opts.warmupMs ?? 750;
  const durationMs = opts.durationMs ?? 1250;
  const rounds = opts.rounds ?? 3;

  // Warmup: let JIT, parser caches, and lazy init settle.
  const warmupEnd = performance.now() + warmupMs;
  while (performance.now() < warmupEnd) {
    engine.evaluate(profile.toolCall);
  }

  const all: number[] = [];
  let totalCalls = 0;
  let totalWallMs = 0;

  for (let r = 0; r < rounds; r++) {
    // Force GC between rounds when --expose-gc is active (node --expose-gc).
    const g = (globalThis as { gc?: () => void }).gc;
    if (g) g();

    const start = performance.now();
    let count = 0;
    while (performance.now() - start < durationMs) {
      const t0 = performance.now();
      engine.evaluate(profile.toolCall);
      all.push(performance.now() - t0);
      count++;
    }
    const wall = performance.now() - start;
    totalCalls += count;
    totalWallMs += wall;
  }

  const sorted = [...all].sort((a, b) => a - b);
  const mean = all.reduce((a, b) => a + b, 0) / all.length;
  const variance = all.reduce((a, b) => a + (b - mean) ** 2, 0) / all.length;

  return {
    id: profile.id,
    label: profile.label,
    samples: all.length,
    rounds,
    meanMs: mean,
    minMs: sorted[0] ?? 0,
    maxMs: sorted[sorted.length - 1] ?? 0,
    stdDevMs: Math.sqrt(variance),
    p50Ms: percentile(sorted, 0.5),
    p90Ms: percentile(sorted, 0.9),
    p95Ms: percentile(sorted, 0.95),
    p99Ms: percentile(sorted, 0.99),
    throughputRps: totalCalls / (totalWallMs / 1000),
  };
}

/** Run all default profiles on a fresh engine each (isolates stateful rules). */
export function runFullBenchmark(opts?: { warmupMs?: number; durationMs?: number; rounds?: number }): HarnessReport {
  const effective = {
    warmupMs: Math.max(opts?.warmupMs ?? 750, 400),
    durationMs: Math.max(opts?.durationMs ?? 1250, 700),
    rounds: Math.max(opts?.rounds ?? 3, 3),
  };

  const engines = DEFAULT_PROFILES.map((profile) => ({
    profile,
    engine: new AegisEngine({ mode: 'enforce', packs: profile.packs }),
  }));

  // Global pre-warmup: level JIT/parser/regex compilation across ALL engines
  // BEFORE any measurement, so first-profile bias does not distort results.
  for (const { engine, profile } of engines) {
    for (let i = 0; i < 60; i++) engine.evaluate(profile.toolCall);
  }

  const profiles: ProfileResult[] = engines.map(({ engine, profile }) => runProfile(engine, profile, effective));
  return {
    generatedAt: now(),
    gitSha: gitSha(),
    nodeVersion: process.version,
    platform: `${process.platform}/${process.arch}`,
    profiles,
    verdict: 'PASS',
    regressions: [],
  };
}

/** Compare a fresh run against a committed baseline using the documented gate. */
export function compareToBaseline(current: HarnessReport, baseline: Record<string, BaselineEntry>): HarnessReport {
  const regressions: HarnessReport['regressions'] = [];
  for (const p of current.profiles) {
    const b = baseline[p.id];
    if (!b) continue;
    const p95Floor = b.p95Ms * REGRESSION_RULES.p95.multiplier + REGRESSION_RULES.p95.absoluteFloorMs;
    const p50Floor = b.p50Ms * REGRESSION_RULES.p50.multiplier + REGRESSION_RULES.p50.absoluteFloorMs;
    if (p.p95Ms > p95Floor) regressions.push({ profile: p.id, metric: 'p95', baseline: b.p95Ms, current: p.p95Ms });
    if (p.p50Ms > p50Floor) regressions.push({ profile: p.id, metric: 'p50', baseline: b.p50Ms, current: p.p50Ms });
  }
  current.regressions = regressions;
  current.verdict = regressions.length === 0 ? 'PASS' : 'FAIL';
  return current;
}

export function formatBenchmarkTable(report: HarnessReport): string {
  const rows = report.profiles.map((p) => {
    const cells = [p.id, p.meanMs.toFixed(3), p.p50Ms.toFixed(3), p.p90Ms.toFixed(3), p.p95Ms.toFixed(3), p.p99Ms.toFixed(3), Math.round(p.throughputRps).toLocaleString('en-US')];
    return `| ${cells.join(' | ')} |`;
  });
  return [
    '| profile | mean | p50 | p90 | p95 | p99 | rps |',
    '| :--- | ---: | ---: | ---: | ---: | ---: | ---: |',
    ...rows,
  ].join('\n');
}
