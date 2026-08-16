/**
 * Aegis Core Workload Latency Benchmark
 *
 * Measures high-precision evaluation latency (P50, P95, P99, Min, Max, Mean, StdDev, Throughput)
 * across core agent tool-call workloads:
 *   1. Simple SELECT (single-statement query parsing & invariant validation)
 *   2. Destructive DELETE (destructive operation / tautology detection)
 *   3. JOIN with Subquery (complex AST traversal & mutation scan)
 *   4. Payment Limit Check (numeric bounds & rate control evaluation)
 *
 * Verifies that steady-state evaluation latency strictly adheres to the <= 1.5ms budget for standard tool calls.
 */

import { performance } from 'node:perf_hooks';
import { AegisEngine, type ToolCall } from '@aegis-kernel/core';

export interface WorkloadBenchmarkSpec {
  id: string;
  name: string;
  category: string;
  toolCall: ToolCall;
  packs: string[];
  expectedAllowed: boolean;
  description: string;
}

export interface WorkloadLatencyMetrics {
  id: string;
  name: string;
  category: string;
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
  budgetMs: number;
  passedBudget: boolean;
  expectedAllowed: boolean;
  actualAllowed: boolean;
}

export interface WorkloadBenchmarkSuiteResult {
  timestamp: string;
  platform: string;
  nodeVersion: string;
  budgetMs: number;
  totalWorkloads: number;
  passedBudgetCount: number;
  allPassedBudget: boolean;
  workloads: WorkloadLatencyMetrics[];
}

export const CORE_WORKLOAD_SPECS: WorkloadBenchmarkSpec[] = [
  {
    id: 'simple-select',
    name: 'Simple SELECT',
    category: 'SQL Invariant',
    toolCall: {
      tool: 'database_exec',
      params: {
        query: 'SELECT name, email FROM customers WHERE id = 42 LIMIT 10',
      },
    },
    packs: ['@aegis/sql-guard'],
    expectedAllowed: true,
    description: 'Single-statement SELECT query AST parsing and limit ceiling verification',
  },
  {
    id: 'destructive-delete',
    name: 'Destructive DELETE',
    category: 'SQL Mutation Guard',
    toolCall: {
      tool: 'database_exec',
      params: {
        query: 'DELETE FROM users WHERE 1=1',
      },
    },
    packs: ['@aegis/sql-guard'],
    expectedAllowed: false,
    description: 'Prohibited destructive DELETE with tautological predicate clause',
  },
  {
    id: 'join-subquery',
    name: 'JOIN with Subquery',
    category: 'Complex SQL AST',
    toolCall: {
      tool: 'database_exec',
      params: {
        query: "WITH recent AS (SELECT id FROM orders WHERE created_at > '2026-01-01') SELECT * FROM customers c JOIN recent r ON c.id = r.id WHERE c.region = 'EMEA' LIMIT 100;",
      },
    },
    packs: ['@aegis/sql-guard'],
    expectedAllowed: true,
    description: 'Multi-statement / CTE join query requiring nested subquery traversal',
  },
  {
    id: 'payment-limit-check',
    name: 'Payment Limit Check',
    category: 'Financial Bounds',
    toolCall: {
      tool: 'payout',
      params: {
        amount: 4500,
        currency: 'USD',
        beneficiary: 'acct_12345',
      },
    },
    packs: ['@aegis/finance-guard', '@aegis/fintech-trade-guard'],
    expectedAllowed: true,
    description: 'Numeric ceiling validation, bounds check, and rate limiter lookup',
  },
];

export const LATENCY_BUDGET_MS = 1.5;

function computePercentile(sortedValues: number[], p: number): number {
  if (sortedValues.length === 0) return 0;
  const index = Math.min(sortedValues.length - 1, Math.floor(p * sortedValues.length));
  return sortedValues[index] ?? sortedValues[sortedValues.length - 1]!;
}

export function benchmarkWorkload(
  engine: AegisEngine,
  spec: WorkloadBenchmarkSpec,
  options: {
    warmupMs?: number;
    durationMs?: number;
    rounds?: number;
    budgetMs?: number;
  } = {}
): WorkloadLatencyMetrics {
  const warmupMs = options.warmupMs ?? 500;
  const durationMs = options.durationMs ?? 1000;
  const rounds = options.rounds ?? 3;
  const budgetMs = options.budgetMs ?? LATENCY_BUDGET_MS;

  // Pre-warmup iterations to settle JIT, AST caches, regexes, and inline caches
  for (let i = 0; i < 500; i++) {
    engine.evaluate(spec.toolCall);
  }

  const warmupEnd = performance.now() + warmupMs;
  let lastVerdict = engine.evaluate(spec.toolCall);
  while (performance.now() < warmupEnd) {
    lastVerdict = engine.evaluate(spec.toolCall);
  }

  // Pre-allocate buffer for high-precision samples to eliminate GC from array allocations
  const MAX_CAPACITY = 200_000;
  const rawBuffer = new Float64Array(MAX_CAPACITY);
  let sampleCount = 0;
  let totalCalls = 0;
  let totalWallMs = 0;

  for (let r = 0; r < rounds; r++) {
    const gc = (globalThis as unknown as { gc?: () => void }).gc;
    if (typeof gc === 'function') {
      gc();
    }

    const roundStart = performance.now();
    let roundCalls = 0;
    while (performance.now() - roundStart < durationMs && sampleCount < MAX_CAPACITY) {
      const t0 = performance.now();
      lastVerdict = engine.evaluate(spec.toolCall);
      const t1 = performance.now();
      rawBuffer[sampleCount++] = t1 - t0;
      roundCalls++;
    }
    const roundWall = performance.now() - roundStart;
    totalCalls += roundCalls;
    totalWallMs += roundWall;
  }

  const sampleLatencies = Array.from(rawBuffer.subarray(0, sampleCount)).sort((a, b) => a - b);
  const sum = sampleLatencies.reduce((acc, v) => acc + v, 0);
  const mean = sum / sampleLatencies.length;
  const variance = sampleLatencies.reduce((acc, v) => acc + (v - mean) ** 2, 0) / sampleLatencies.length;
  const stdDev = Math.sqrt(variance);

  const p50 = computePercentile(sampleLatencies, 0.5);
  const p90 = computePercentile(sampleLatencies, 0.9);
  const p95 = computePercentile(sampleLatencies, 0.95);
  const p99 = computePercentile(sampleLatencies, 0.99);
  const throughputRps = totalCalls / (totalWallMs / 1000);

  // Budget verification: P99, P95, and P50 must all stay within the target budget threshold
  const passedBudget = p99 <= budgetMs && p95 <= budgetMs && p50 <= budgetMs;

  return {
    id: spec.id,
    name: spec.name,
    category: spec.category,
    samples: sampleLatencies.length,
    rounds,
    meanMs: mean,
    minMs: sampleLatencies[0] ?? 0,
    maxMs: sampleLatencies[sampleLatencies.length - 1] ?? 0,
    stdDevMs: stdDev,
    p50Ms: p50,
    p90Ms: p90,
    p95Ms: p95,
    p99Ms: p99,
    throughputRps,
    budgetMs,
    passedBudget,
    expectedAllowed: spec.expectedAllowed,
    actualAllowed: lastVerdict.allowed,
  };
}

export function runCoreWorkloadBenchmarks(options: {
  warmupMs?: number;
  durationMs?: number;
  rounds?: number;
  budgetMs?: number;
  workloads?: WorkloadBenchmarkSpec[];
} = {}): WorkloadBenchmarkSuiteResult {
  const workloads = options.workloads ?? CORE_WORKLOAD_SPECS;
  const budgetMs = options.budgetMs ?? LATENCY_BUDGET_MS;

  const results: WorkloadLatencyMetrics[] = [];

  for (const spec of workloads) {
    const engine = new AegisEngine({
      mode: 'enforce',
      packs: spec.packs,
      logging: {
        enabled: false,
      },
    });

    // Engine level pre-warmup
    for (let i = 0; i < 100; i++) {
      engine.evaluate(spec.toolCall);
    }

    const metric = benchmarkWorkload(engine, spec, {
      warmupMs: options.warmupMs ?? 500,
      durationMs: options.durationMs ?? 1000,
      rounds: options.rounds ?? 3,
      budgetMs,
    });
    results.push(metric);
  }

  const passedBudgetCount = results.filter((r) => r.passedBudget).length;

  return {
    timestamp: new Date().toISOString(),
    platform: `${process.platform}/${process.arch}`,
    nodeVersion: process.version,
    budgetMs,
    totalWorkloads: results.length,
    passedBudgetCount,
    allPassedBudget: passedBudgetCount === results.length,
    workloads: results,
  };
}

export function formatBenchmarkReportTable(suiteResult: WorkloadBenchmarkSuiteResult): string {
  const headers = [
    'Workload',
    'Category',
    'Samples',
    'Mean (ms)',
    'P50 (ms)',
    'P90 (ms)',
    'P95 (ms)',
    'P99 (ms)',
    'Throughput (ops/s)',
    'Budget (< 1.5ms)',
    'Verdict',
  ];

  const rows = suiteResult.workloads.map((w) => [
    w.name,
    w.category,
    w.samples.toLocaleString('en-US'),
    w.meanMs.toFixed(4),
    w.p50Ms.toFixed(4),
    w.p90Ms.toFixed(4),
    w.p95Ms.toFixed(4),
    w.p99Ms.toFixed(4),
    Math.round(w.throughputRps).toLocaleString('en-US'),
    `${w.budgetMs.toFixed(1)} ms`,
    w.passedBudget ? 'PASS' : 'FAIL',
  ]);

  const colWidths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((row) => row[i]!.length))
  );

  const formatRow = (cells: string[]) =>
    `| ${cells.map((c, i) => c.padEnd(colWidths[i]!)).join(' | ')} |`;

  const separator = `| ${colWidths.map((w) => '-'.repeat(w)).join(' | ')} |`;

  return [
    formatRow(headers),
    separator,
    ...rows.map((r) => formatRow(r)),
  ].join('\n');
}

// CLI direct runner
if (process.argv[1]?.endsWith('benchmark.ts') || process.argv[1]?.endsWith('benchmark.js')) {
  console.log('🚀 Running Aegis Invariant Kernel Core Workload Latency Benchmarks...\n');
  console.log(`Target SLA Budget: < ${LATENCY_BUDGET_MS}ms per tool call`);
  console.log(`Workloads: ${CORE_WORKLOAD_SPECS.map((w) => w.name).join(', ')}\n`);

  const suiteResult = runCoreWorkloadBenchmarks();
  const table = formatBenchmarkReportTable(suiteResult);
  console.log(table);
  console.log('\n--- Benchmark Summary ---');
  console.log(`Overall Status: ${suiteResult.allPassedBudget ? 'PASSED (ALL WORKLOADS UNDER 1.5ms BUDGET)' : 'FAILED'}`);
  console.log(`Workloads Passing Budget: ${suiteResult.passedBudgetCount}/${suiteResult.totalWorkloads}`);

  for (const w of suiteResult.workloads) {
    console.log(`  • ${w.name.padEnd(22)}: P50=${w.p50Ms.toFixed(4)}ms | P95=${w.p95Ms.toFixed(4)}ms | P99=${w.p99Ms.toFixed(4)}ms | Throughput=${Math.round(w.throughputRps).toLocaleString()} ops/sec [${w.passedBudget ? 'PASS' : 'FAIL'}]`);
  }

  if (!suiteResult.allPassedBudget) {
    process.exit(1);
  }
}
