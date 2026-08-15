import { AegisEngine, type ToolCall } from '@aegis-kernel/core';
import { performance } from 'node:perf_hooks';

export interface BenchmarkVector {
  id: string;
  dataset: 'InjecAgent' | 'AgentDojo' | 'MCPTox' | 'Internal';
  category: string;
  isAttack: boolean;
  toolCall: ToolCall;
  expectedVerdict: 'BLOCKED' | 'ALLOWED';
}

export interface BenchmarkReport {
  totalVectors: number;
  maliciousTotal: number;
  maliciousBlocked: number;
  maliciousBlockRatePercent: number;
  benignTotal: number;
  benignPassed: number;
  benignPassRatePercent: number;
  f1ScorePercent: number;
  latencies: number[];
  avgLatencyMs: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  timestamp: string;
}

export class ExternalBenchmarkRunner {
  private engine: AegisEngine;

  constructor(engine?: AegisEngine) {
    this.engine =
      engine ||
      new AegisEngine({
        mode: 'enforce',
        packs: [
          '@aegis/sql-guard',
          '@aegis/finance-guard',
          '@aegis/data-guard',
          '@aegis/hipaa-guard',
          '@aegis/pci-dss-guard',
          '@aegis/soc2-guard',
        ],
      });
  }

  public evaluateVectors(vectors: BenchmarkVector[]): BenchmarkReport {
    let maliciousTotal = 0;
    let maliciousBlocked = 0;
    let benignTotal = 0;
    let benignPassed = 0;
    const latencies: number[] = [];

    for (const vec of vectors) {
      const t0 = performance.now();
      const verdict = this.engine.evaluate(vec.toolCall);
      const t1 = performance.now();
      latencies.push(t1 - t0);

      if (vec.isAttack) {
        maliciousTotal++;
        if (!verdict.allowed) {
          maliciousBlocked++;
        }
      } else {
        benignTotal++;
        if (verdict.allowed) {
          benignPassed++;
        }
      }
    }

    latencies.sort((a, b) => a - b);
    const total = vectors.length;
    const avgLatency = total > 0 ? latencies.reduce((a, b) => a + b, 0) / total : 0;
    const p50 = latencies[Math.floor(total * 0.5)] || 0;
    const p95 = latencies[Math.floor(total * 0.95)] || 0;
    const p99 = latencies[Math.floor(total * 0.99)] || 0;

    const blockRate = maliciousTotal > 0 ? (maliciousBlocked / maliciousTotal) * 100 : 100;
    const passRate = benignTotal > 0 ? (benignPassed / benignTotal) * 100 : 100;

    const precision =
      maliciousBlocked + (benignTotal - benignPassed) > 0
        ? maliciousBlocked / (maliciousBlocked + (benignTotal - benignPassed))
        : 1.0;
    const recall = maliciousTotal > 0 ? maliciousBlocked / maliciousTotal : 1.0;
    const f1 = precision + recall > 0 ? ((2 * precision * recall) / (precision + recall)) * 100 : 100;

    return {
      totalVectors: total,
      maliciousTotal,
      maliciousBlocked,
      maliciousBlockRatePercent: Number(blockRate.toFixed(2)),
      benignTotal,
      benignPassed,
      benignPassRatePercent: Number(passRate.toFixed(2)),
      f1ScorePercent: Number(f1.toFixed(2)),
      latencies,
      avgLatencyMs: Number(avgLatency.toFixed(3)),
      p50LatencyMs: Number(p50.toFixed(3)),
      p95LatencyMs: Number(p95.toFixed(3)),
      p99LatencyMs: Number(p99.toFixed(3)),
      timestamp: new Date().toISOString(),
    };
  }
}
