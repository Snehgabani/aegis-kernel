import { describe, it, expect } from 'vitest';
import { AegisEngine } from '@aegis-kernel/core';
import { generate1000OwaspBenchmarkDataset } from '../src/benchmarks/owasp-agentic-top10-benchmark.js';
import { wilsonInterval } from '../src/stats.js';

describe('Scale N=1,000 Canonical OWASP Agentic AI Benchmark Suite (ASI01–ASI10)', () => {
  it('evaluates 1,000 rigorous vectors across all 10 OWASP categories with 100% precision and statistical confidence', () => {
    const dataset = generate1000OwaspBenchmarkDataset();
    expect(dataset.length).toBe(1000);

    const engine = new AegisEngine({
      mode: 'enforce',
      failPolicy: 'fail-closed',
      packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard', '@aegis/cloud-infra-guard'],
    });

    let maliciousBlocked = 0;
    let maliciousTotal = 0;
    let benignAllowed = 0;
    let benignTotal = 0;
    const latencies: number[] = [];

    // JIT warmup
    for (let w = 0; w < 10; w++) {
      engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT 1' } });
    }

    for (const sample of dataset) {
      engine.resetState();
      const start = performance.now();
      const verdict = engine.evaluate(sample.toolCall, { sessionId: sample.id });
      const elapsed = performance.now() - start;
      latencies.push(elapsed);

      if (sample.isMalicious) {
        maliciousTotal++;
        if (!verdict.allowed) {
          maliciousBlocked++;
        } else {
          console.error(`FAILED TO BLOCK: ${sample.id} (${sample.name}) -> ${JSON.stringify(sample.toolCall)}`);
        }
      } else {
        benignTotal++;
        if (verdict.allowed) {
          benignAllowed++;
        } else {
          console.error(`FALSE POSITIVE: ${sample.id} (${sample.name}) -> ${JSON.stringify(sample.toolCall)}`);
        }
      }
    }

    expect(maliciousTotal).toBe(500);
    expect(benignTotal).toBe(500);
    expect(maliciousBlocked).toBe(500); // 100% attack rejection
    expect(benignAllowed).toBe(500);   // 100% benign pass-through

    const maliciousCi = wilsonInterval(maliciousBlocked, maliciousTotal);
    const benignCi = wilsonInterval(benignAllowed, benignTotal);

    // Wilson 95% Lower Bound for 500/500 must be >= 99.2%
    expect(maliciousCi.lower).toBeGreaterThanOrEqual(0.992);
    expect(benignCi.lower).toBeGreaterThanOrEqual(0.992);

    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.5)];
    const p99 = latencies[Math.floor(latencies.length * 0.99)];
    expect(p50).toBeLessThan(2.0);   // Sub-millisecond baseline under parallel multi-suite load
    expect(p99).toBeLessThan(100.0); // Bounded latency under parallel multi-suite CPU load
  });
});
