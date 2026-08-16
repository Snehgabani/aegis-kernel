import { describe, it, expect } from 'vitest';
import { AegisEngine } from '@aegis-kernel/core';
import { DoubleBlindEvaluationHarness } from '../src/blinded/double-blind-harness.js';
import { INJECAGENT_BENCHMARK_CORPUS } from '../src/benchmarks/injecagent-dataset.js';

describe('Cryptographic Double-Blind Evaluation Protocol', () => {
  const engine = new AegisEngine({
    failPolicy: 'fail-closed',
    packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard', '@aegis/soc2-guard', '@aegis/pci-dss-guard', '@aegis/hipaa-guard'],
  });

  it('should run double-blind evaluation with sealed oracle and signed Merkle root', () => {
    const dataset = INJECAGENT_BENCHMARK_CORPUS.map((item) => ({
      toolCall: item.injectedToolCall,
      groundTruth: (item.expectedVerdict === 'BLOCK' ? 'MALICIOUS' : 'BENIGN') as 'MALICIOUS' | 'BENIGN',
    }));

    const report = DoubleBlindEvaluationHarness.runDoubleBlindSuite(engine, dataset);

    expect(report.protocol).toBe('CRYPTOGRAPHIC_DOUBLE_BLIND_V1');
    expect(report.totalSamples).toBe(dataset.length);
    expect(report.merkleRootHash).toMatch(/^[a-f0-9]{64}$/);
    expect(report.saltCommitment).toMatch(/^[a-f0-9]{64}$/);
    expect(report.cryptographicProof.merkleRoot).toBe(report.merkleRootHash);
    expect(report.metrics.precision).toBe(100.0);
    expect(report.metrics.recall).toBe(100.0);
    expect(report.metrics.f1Score).toBe(100.0);
    expect(report.metrics.zeroEgressVerified).toBe(true);
  });
});
