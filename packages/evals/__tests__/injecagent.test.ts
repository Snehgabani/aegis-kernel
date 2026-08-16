import { describe, it, expect } from 'vitest';
import { AegisEngine } from '@aegis-kernel/core';
import { INJECAGENT_BENCHMARK_CORPUS } from '../src/benchmarks/injecagent-dataset.js';

describe('InjecAgent Academic Benchmark Suite (ACL/EMNLP 2024)', () => {
  const engine = new AegisEngine({
    failPolicy: 'fail-closed',
    packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard', '@aegis/soc2-guard', '@aegis/hipaa-guard'],
  });

  it('should evaluate all Direct Harm (DH) vectors and block 100% of malicious attempts', () => {
    const dhVectors = INJECAGENT_BENCHMARK_CORPUS.filter(v => v.category === 'DIRECT_HARM' && v.expectedVerdict === 'BLOCK');
    expect(dhVectors.length).toBeGreaterThan(0);

    for (const testCase of dhVectors) {
      const verdict = engine.evaluate(testCase.injectedToolCall);
      expect(verdict.allowed).toBe(false);
      expect(verdict.violations.length).toBeGreaterThan(0);
    }
  });

  it('should evaluate all Data Exfiltration (DE) vectors and block 100% of exfiltrations', () => {
    const deVectors = INJECAGENT_BENCHMARK_CORPUS.filter(v => v.category === 'DATA_EXFILTRATION' && v.expectedVerdict === 'BLOCK');
    expect(deVectors.length).toBeGreaterThan(0);

    for (const testCase of deVectors) {
      const verdict = engine.evaluate(testCase.injectedToolCall);
      expect(verdict.allowed).toBe(false);
      expect(verdict.violations.length).toBeGreaterThan(0);
    }
  });

  it('should preserve utility for benign user tool calls (0 false positives)', () => {
    const benignVectors = INJECAGENT_BENCHMARK_CORPUS.filter(v => v.expectedVerdict === 'ALLOW');
    expect(benignVectors.length).toBeGreaterThan(0);

    for (const testCase of benignVectors) {
      const verdict = engine.evaluate(testCase.injectedToolCall);
      expect(verdict.allowed).toBe(true);
      expect(verdict.violations.length).toBe(0);
    }
  });
});
