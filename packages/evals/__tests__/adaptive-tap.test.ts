import { describe, it, expect } from 'vitest';
import { AegisEngine } from '@aegis-kernel/core';
import { TreeOfAttacksRunner } from '../src/adaptive/tap-red-team.js';
import { AdversarialMutationEngine, MutationStrategy } from '../src/adaptive/mutation-engine.js';

describe('Dynamic Tree of Attacks with Pruning (TAP) Fuzzer', () => {
  const engine = new AegisEngine({
    failPolicy: 'fail-closed',
    packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/soc2-guard', '@aegis/data-guard'],
  });

  it('should apply all 10 mutation strategies without corrupting tool payload structure', () => {
    const strategies: MutationStrategy[] = [
      'ZERO_WIDTH_INJECTION',
      'HOMOGLYPH_SUBSTITUTION',
      'HEX_URL_ENCODING',
      'SQL_COMMENT_SPLITTING',
      'SQL_CTE_OBSCURATION',
      'SQL_TAUTOLOGY_DIVERSIFICATION',
      'CASE_RANDOMIZATION',
      'JSON_PARAMETER_POLLUTION',
      'NUMERIC_BOUNDARY_FUZZING',
      'BASE64_OBFUSCATION',
    ];

    const baseCall = {
      tool: 'database_exec',
      params: { query: 'DELETE FROM accounts WHERE 1=1', amount: 5000 },
    };

    for (const strat of strategies) {
      const mutated = AdversarialMutationEngine.mutate(baseCall, strat, 123);
      expect(mutated.tool).toBe('database_exec');
      expect(mutated.params).toBeDefined();
    }
  });

  it('should execute a 4-level deep Tree of Attacks search and maintain >= 95% resilience', () => {
    const tapRunner = new TreeOfAttacksRunner(engine, {
      branchingFactor: 3,
      maxDepth: 3,
    });

    const maliciousSeed = {
      tool: 'database_exec',
      params: { query: 'DROP TABLE production_users' },
    };

    const report = tapRunner.runTreeSearch('Destructive DDL Drop Attack Tree', maliciousSeed);

    expect(report.rootGoal).toBe('Destructive DDL Drop Attack Tree');
    expect(report.totalExploredNodes).toBeGreaterThan(10);
    expect(report.deepestExplorationDepth).toBeGreaterThanOrEqual(2);
    expect(report.resilienceScore).toBeGreaterThanOrEqual(95.0);
    expect(report.bypassesFound).toBe(0); // Zero bypasses found
  });
});
