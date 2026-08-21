import { describe, it, expect } from 'vitest';
import {
  SecListsEvaluator,
  CANONICAL_SECLISTS_SAMPLES,
} from '../src/benchmarks/seclists-adapter.js';

describe('SecLists & Exploit-DB Real-World Historic CVE Evaluation Suite', () => {
  it('evaluates SecLists real-world historic SQLi, CMDi, and SSRF attacks with 100% precision', () => {
    const report = SecListsEvaluator.evaluateCases(CANONICAL_SECLISTS_SAMPLES);

    expect(report.benchmark).toBe('seclists-cve');
    expect(report.metrics.totalCases).toBe(15);
    expect(report.metrics.maliciousTotal).toBe(11);
    expect(report.metrics.maliciousBlocked).toBe(11);
    expect(report.metrics.benignTotal).toBe(4);
    expect(report.metrics.benignAllowed).toBe(4);
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
