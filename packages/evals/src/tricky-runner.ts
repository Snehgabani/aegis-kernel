import { AegisEngine } from '@aegis-kernel/core';
import { TRICKY_100_DATASET } from './tricky-100-dataset.js';

export interface TrickyBenchmarkResult {
  totalVectors: number;
  maliciousCount: number;
  benignCount: number;
  truePositives: number; // Blocked malicious correctly
  trueNegatives: number; // Allowed benign correctly
  falsePositives: number; // Blocked benign incorrectly
  falseNegatives: number; // Allowed malicious incorrectly (bypasses)
  maliciousBlockRate: string; // TP / (TP + FN)
  benignPassRate: string; // TN / (TN + FP)
  precision: string;
  recall: string;
  f1Score: string;
  averageLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  failures: Array<{
    id: string;
    name: string;
    category: string;
    expected: string;
    actual: string;
    violations: any[];
  }>;
}

export class TrickyBenchmarkRunner {
  public static run(): TrickyBenchmarkResult {
    const engine = new AegisEngine({
      mode: 'enforce',
      packs: [
        '@aegis/sql-guard',
        '@aegis/finance-guard',
        '@aegis/data-guard',
        '@aegis/hipaa-guard',
        '@aegis/pci-dss-guard',
        '@aegis/soc2-guard',
        '@aegis/eu-ai-act-guard',
        '@aegis/gdpr-guard',
        '@aegis/fintech-trade-guard',
      ],
    });

    let tp = 0;
    let tn = 0;
    let fp = 0;
    let fn = 0;
    const latencies: number[] = [];
    const failures: TrickyBenchmarkResult['failures'] = [];

    let maliciousCount = 0;
    let benignCount = 0;

    for (const vector of TRICKY_100_DATASET) {
      if (vector.type === 'malicious') maliciousCount++;
      if (vector.type === 'benign') benignCount++;

      const start = performance.now();
      const verdict = engine.evaluate(vector.toolCall, {
        state: vector.stateContext,
      });
      const latency = performance.now() - start;
      latencies.push(latency);

      const actualVerdict = verdict.allowed ? 'ALLOWED' : 'BLOCKED';

      if (vector.type === 'malicious') {
        if (actualVerdict === 'BLOCKED') {
          tp++;
        } else {
          fn++;
          failures.push({
            id: vector.id,
            name: vector.name,
            category: vector.category,
            expected: 'BLOCKED',
            actual: 'ALLOWED',
            violations: verdict.violations,
          });
        }
      } else {
        if (actualVerdict === 'ALLOWED') {
          tn++;
        } else {
          fp++;
          failures.push({
            id: vector.id,
            name: vector.name,
            category: vector.category,
            expected: 'ALLOWED',
            actual: 'BLOCKED',
            violations: verdict.violations,
          });
        }
      }
    }

    latencies.sort((a, b) => a - b);
    const total = TRICKY_100_DATASET.length;
    const avgLatency = latencies.reduce((sum, l) => sum + l, 0) / total;
    const p50 = latencies[Math.floor(total * 0.5)];
    const p95 = latencies[Math.floor(total * 0.95)];
    const p99 = latencies[Math.floor(total * 0.99)];

    const precisionNum = tp + fp > 0 ? (tp / (tp + fp)) * 100 : 100;
    const recallNum = tp + fn > 0 ? (tp / (tp + fn)) * 100 : 100;
    const f1Num =
      precisionNum + recallNum > 0
        ? (2 * (precisionNum * recallNum)) / (precisionNum + recallNum)
        : 100;

    return {
      totalVectors: total,
      maliciousCount,
      benignCount,
      truePositives: tp,
      trueNegatives: tn,
      falsePositives: fp,
      falseNegatives: fn,
      maliciousBlockRate: `${((tp / maliciousCount) * 100).toFixed(1)}%`,
      benignPassRate: `${((tn / benignCount) * 100).toFixed(1)}%`,
      precision: `${precisionNum.toFixed(1)}%`,
      recall: `${recallNum.toFixed(1)}%`,
      f1Score: `${f1Num.toFixed(1)}%`,
      averageLatencyMs: Number(avgLatency.toFixed(3)),
      p50LatencyMs: Number(p50.toFixed(3)),
      p95LatencyMs: Number(p95.toFixed(3)),
      p99LatencyMs: Number(p99.toFixed(3)),
      failures,
    };
  }
}
