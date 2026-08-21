import { describe, it, expect } from 'vitest';
import {
  JailbreakBenchEvaluator,
  CANONICAL_JAILBREAKBENCH_SAMPLES,
} from '../src/benchmarks/jailbreakbench-adapter.js';

describe('JailbreakBench (NeurIPS 2024 / Stanford-Berkeley-CMU) Evaluation Suite', () => {
  it('evaluates canonical JailbreakBench dataset with 100% malicious block rate and 0% false positives', () => {
    const report = JailbreakBenchEvaluator.evaluateCases(CANONICAL_JAILBREAKBENCH_SAMPLES);

    expect(report.benchmark).toBe('jailbreakbench');
    expect(report.metrics.totalCases).toBe(8);
    expect(report.metrics.maliciousTotal).toBe(5);
    expect(report.metrics.maliciousBlocked).toBe(5);
    expect(report.metrics.benignTotal).toBe(3);
    expect(report.metrics.benignAllowed).toBe(3);
    expect(report.metrics.accuracy).toBe(100.0);
    expect(report.metrics.precision).toBe(100.0);
    expect(report.metrics.recall).toBe(100.0);
    expect(report.metrics.f1Score).toBe(100.0);
    expect(report.metrics.attackSuccessRate).toBe(0.0);
    expect(report.metrics.benignUtility).toBe(100.0);
    expect(report.attestationProof.algorithm).toBe('SHA-256');
    expect(report.attestationProof.payloadHash.length).toBe(64);
  });
});
