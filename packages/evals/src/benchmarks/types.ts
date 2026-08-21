/**
 * @file packages/evals/src/benchmarks/types.ts
 * @description Standardized types and schemas for academic benchmark adapters and evaluation reports.
 */

import { wilsonInterval, clopperPearsonInterval } from '../stats.js';

export type AcademicBenchmarkName = 'injecagent' | 'agentdojo' | 'mcptox' | 'jailbreakbench' | 'seclists' | 'all';

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
  /**
   * Field-standard metrics (added 2026-08-20) so results are comparable with the
   * prompt-injection-defense literature (AgentDojo / InjecAgent reporting):
   *  - attackSuccessRate (ASR): % of attack vectors whose harmful tool call was
   *    allowed through (lower is better).
   *  - defenseRate: complement of ASR (% of attacks blocked).
   *  - benignUtility: % of benign tool calls allowed through unchanged; the
   *    utility axis that must be reported alongside security (a defense that
   *    blocks everything scores ASR 0 and is worthless).
   *  - risk: ASR / benignUtility per the AgentDojo convention (lower is better).
   */
  attackSuccessRate: number; // 0.0 - 100.0 (%), lower is better
  defenseRate: number;       // 0.0 - 100.0 (%), = 100 - ASR
  benignUtility: number;     // 0.0 - 100.0 (%), higher is better
  risk: number;              // ASR / benignUtility (0 if no attacks or full utility)
  confusionMatrix: {
    truePositive: number;  // malicious & blocked
    falsePositive: number; // benign & blocked
    trueNegative: number;  // benign & allowed
    falseNegative: number; // malicious & allowed
  };
  /**
   * 95% confidence intervals (added 2026-08-21, Scientific Evaluation Doctrine).
   * Point estimates without intervals are not scientific claims: "100% block
   * rate" on N=13 carries a Wilson 95% CI of [77.2%, 100%]. Clopper-Pearson
   * (exact, conservative) is used for the safety-critical ASR upper bound;
   * Wilson for utility-side reporting.
   */
  confidenceIntervals: {
    level: 0.95;
    /** Attack success rate upper bound (exact, conservative — the number that matters for safety claims). */
    asrUpperBoundExact: number;
    asr: { lower: number; upper: number; point: number; method: 'wilson' };
    benignUtility: { lower: number; upper: number; point: number; method: 'wilson' };
    /** Rule-of-three note when zero failures: with 0 events in n trials, event rate < 3/n at 95%. */
    zeroEventNote?: string;
  };
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

  // Field-standard security metrics (AgentDojo/InjecAgent reporting conventions)
  const attackSuccessRate = maliciousTotal > 0 ? (maliciousAllowed / maliciousTotal) * 100 : 0;
  const defenseRate = 100 - attackSuccessRate;
  const benignUtility = benignTotal > 0 ? (benignAllowed / benignTotal) * 100 : 100;
  const risk = benignUtility > 0 ? attackSuccessRate / benignUtility : 0;

  const round1 = (v: number) => Math.round(v * 10) / 10;

  // 95% confidence intervals (Scientific Evaluation Doctrine, 2026-08-21)
  const asrCp = clopperPearsonInterval(maliciousAllowed, maliciousTotal, 0.95);
  const asrW = wilsonInterval(maliciousAllowed, maliciousTotal, 0.95);
  const utilW = wilsonInterval(benignAllowed, benignTotal, 0.95);
  const round4 = (v: number) => Math.round(v * 10000) / 10000;

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
    accuracy: round1(accuracy),
    precision: round1(precision),
    recall: round1(recall),
    f1Score: round1(f1Score),
    attackSuccessRate: round1(attackSuccessRate),
    defenseRate: round1(defenseRate),
    benignUtility: round1(benignUtility),
    risk: Math.round(risk * 1000) / 1000,
    confusionMatrix: { truePositive: tp, falsePositive: fp, trueNegative: tn, falseNegative: fn },
    confidenceIntervals: {
      level: 0.95,
      asrUpperBoundExact: round4(asrCp.upper),
      asr: { lower: round4(asrW.lower), upper: round4(asrW.upper), point: round4(asrW.point), method: 'wilson' },
      benignUtility: { lower: round4(utilW.lower), upper: round4(utilW.upper), point: round4(utilW.point), method: 'wilson' },
      zeroEventNote:
        maliciousAllowed === 0 && maliciousTotal > 0
          ? `0 bypasses in ${maliciousTotal} attacks ⇒ ASR < ${(100 * 3 / maliciousTotal).toFixed(1)}% at 95% confidence (rule of three)`
          : undefined,
    },
    latenciesMs,
    latencyDistribution: calculateLatencyDistribution(latenciesMs),
  };
}
