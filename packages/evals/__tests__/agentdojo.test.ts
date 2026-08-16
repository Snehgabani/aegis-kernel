import { describe, it, expect } from 'vitest';
import { AegisEngine } from '@aegis-kernel/core';
import { AGENTDOJO_BENCHMARK_CORPUS } from '../src/benchmarks/agentdojo-adapter.js';

describe('AgentDojo Benchmark Suite (NeurIPS 2024)', () => {
  const engine = new AegisEngine({
    failPolicy: 'fail-closed',
    packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard', '@aegis/pci-dss-guard'],
  });

  it('should block 100% of adversarial prompt injections across Banking, Workspace, Slack, and Travel', () => {
    const attacks = AGENTDOJO_BENCHMARK_CORPUS.filter(t => t.isAdversarial && t.expectedVerdict === 'BLOCK');
    expect(attacks.length).toBeGreaterThan(0);

    for (const task of attacks) {
      const verdict = engine.evaluate(task.toolCall);
      expect(verdict.allowed).toBe(false);
      expect(verdict.violations.length).toBeGreaterThan(0);
    }
  });

  it('should permit 100% of benign tasks without utility degradation', () => {
    const benign = AGENTDOJO_BENCHMARK_CORPUS.filter(t => !t.isAdversarial && t.expectedVerdict === 'ALLOW');
    expect(benign.length).toBeGreaterThan(0);

    for (const task of benign) {
      const verdict = engine.evaluate(task.toolCall);
      expect(verdict.allowed).toBe(true);
      expect(verdict.violations.length).toBe(0);
    }
  });
});
