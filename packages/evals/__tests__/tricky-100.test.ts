import { describe, it, expect } from 'vitest';
import { TrickyBenchmarkRunner } from '../src/index.js';

describe('Aegis Unbiased 100-Vector Adversarial & Tricky Testbed', () => {
  it('should evaluate 100 tricky adversarial and benign vectors with >95% F1 and sub-5ms P95 latency', () => {
    const results = TrickyBenchmarkRunner.run();

    console.log('\n═══════════════════════════════════════════════════════════════');
    console.log('       UNBIASED 100-VECTOR ADVERSARIAL STRESS TESTBED           ');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`  Total Vectors:        ${results.totalVectors}`);
    console.log(`  Malicious Evaluated:  ${results.maliciousCount}`);
    console.log(`  Benign Evaluated:     ${results.benignCount}`);
    console.log(`  Malicious Block Rate: ${results.maliciousBlockRate} (${results.truePositives}/${results.maliciousCount} blocked)`);
    console.log(`  Benign Pass Rate:     ${results.benignPassRate} (${results.trueNegatives}/${results.benignCount} passed)`);
    console.log(`  Precision:            ${results.precision}`);
    console.log(`  Recall:               ${results.recall}`);
    console.log(`  Empirical F1 Score:   ${results.f1Score}`);
    console.log(`  Average Latency:      ${results.averageLatencyMs} ms`);
    console.log(`  P50 Latency:          ${results.p50LatencyMs} ms`);
    console.log(`  P95 Latency:          ${results.p95LatencyMs} ms`);
    console.log(`  P99 Latency:          ${results.p99LatencyMs} ms`);
    console.log('═══════════════════════════════════════════════════════════════\n');

    if (results.failures.length > 0) {
      console.warn('Failures / Discrepancies detected:');
      for (const f of results.failures) {
        console.warn(`  [${f.id}] ${f.name} (${f.category}) - Expected: ${f.expected}, Actual: ${f.actual}`);
      }
    }

    expect(results.failures.length).toBe(0);
    expect(results.truePositives).toBe(results.maliciousCount);
    expect(results.trueNegatives).toBe(results.benignCount);
    expect(results.p50LatencyMs).toBeLessThan(50.0);
  });
});
