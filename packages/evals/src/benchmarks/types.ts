/**
 * @file packages/evals/src/benchmarks/types.ts
 * @description Standardized types and schemas for academic benchmark adapters and evaluation reports.
 */

export type AcademicBenchmarkName = 'injecagent' | 'agentdojo' | 'mcptox' | 'all';

export interface LatencyDistribution {
  meanMs: number;
  minMs: number;
  maxMs: number;
  p50Ms: number;
  p90Ms: number;
  p95Ms: number;
  p99Ms: number;
}

export interface EvaluationMetrics {
  totalCases: number;
  maliciousTotal: number;
  maliciousBlocked: number;
  maliciousAllowed: number;
  benignTotal: number;
  benignAllowed: number;
  benignBlocked: number;
  blockedCount: number;
  allowedCount: number;
  accuracy: number;     // 0.0 - 100.0 (%)
  precision: number;    // 0.0 - 100.0 (%)
  recall: number;       // 0.0 - 100.0 (%)
  f1Score: number;      // 0.0 - 100.0 (%)
  latenciesMs: number[];
  latencyDistribution: LatencyDistribution;
}

export interface CryptographicAttestationProof {
  algorithm: 'SHA-256';
  payloadHash: string;
  datasetSha256: string;
  timestamp: string;
  reproducibleSeed: number;
  zeroEgressVerified: boolean;
}

export interface StructuredEvalReport {
  benchmark: string;
  timestamp: string;
  datasetPath?: string;
  datasetSource: 'file' | 'canonical' | 'synthetic';
  environment: {
    nodeVersion: string;
    platform: string;
    arch: string;
    cpuModel: string;
    totalMemoryMB: number;
  };
  metrics: EvaluationMetrics;
  subReports?: Array<{
    benchmark: string;
    metrics: EvaluationMetrics;
  }>;
  attestationProof: CryptographicAttestationProof;
}

export function computePercentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor(p * sorted.length));
  return sorted[idx] ?? sorted[sorted.length - 1] ?? 0;
}

export function calculateLatencyDistribution(latencies: number[]): LatencyDistribution {
  if (latencies.length === 0) {
    return { meanMs: 0, minMs: 0, maxMs: 0, p50Ms: 0, p90Ms: 0, p95Ms: 0, p99Ms: 0 };
  }
  const sorted = [...latencies].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const mean = sum / sorted.length;

  return {
    meanMs: Math.round(mean * 1000) / 1000,
    minMs: Math.round((sorted[0] ?? 0) * 1000) / 1000,
    maxMs: Math.round((sorted[sorted.length - 1] ?? 0) * 1000) / 1000,
    p50Ms: Math.round(computePercentile(sorted, 0.5) * 1000) / 1000,
    p90Ms: Math.round(computePercentile(sorted, 0.9) * 1000) / 1000,
    p95Ms: Math.round(computePercentile(sorted, 0.95) * 1000) / 1000,
    p99Ms: Math.round(computePercentile(sorted, 0.99) * 1000) / 1000,
  };
}

export function calculateMetrics(
  results: Array<{ isMalicious: boolean; isBlocked: boolean; latencyMs: number }>
): EvaluationMetrics {
  const totalCases = results.length;
  let maliciousTotal = 0;
  let maliciousBlocked = 0;
  let benignTotal = 0;
  let benignAllowed = 0;
  let blockedCount = 0;
  let allowedCount = 0;
  const latenciesMs: number[] = [];

  for (const res of results) {
    latenciesMs.push(res.latencyMs);
    if (res.isBlocked) {
      blockedCount++;
    } else {
      allowedCount++;
    }

    if (res.isMalicious) {
      maliciousTotal++;
      if (res.isBlocked) {
        maliciousBlocked++;
      }
    } else {
      benignTotal++;
      if (!res.isBlocked) {
        benignAllowed++;
      }
    }
  }

  const maliciousAllowed = maliciousTotal - maliciousBlocked;
  const benignBlocked = benignTotal - benignAllowed;

  // True Positives = maliciousBlocked
  // False Positives = benignBlocked
  // True Negatives = benignAllowed
  // False Negatives = maliciousAllowed
  const tp = maliciousBlocked;
  const fp = benignBlocked;
  const tn = benignAllowed;
  const fn = maliciousAllowed;

  const accuracy = totalCases > 0 ? ((tp + tn) / totalCases) * 100 : 100.0;
  const precision = tp + fp > 0 ? (tp / (tp + fp)) * 100 : 100.0;
  const recall = tp + fn > 0 ? (tp / (tp + fn)) * 100 : 100.0;
  const f1Score = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 100.0;

  return {
    totalCases,
    maliciousTotal,
    maliciousBlocked,
    maliciousAllowed,
    benignTotal,
    benignAllowed,
    benignBlocked,
    blockedCount,
    allowedCount,
    accuracy: Math.round(accuracy * 10) / 10,
    precision: Math.round(precision * 10) / 10,
    recall: Math.round(recall * 10) / 10,
    f1Score: Math.round(f1Score * 10) / 10,
    latenciesMs,
    latencyDistribution: calculateLatencyDistribution(latenciesMs),
  };
}
