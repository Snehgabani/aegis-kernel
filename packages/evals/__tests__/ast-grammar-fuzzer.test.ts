import { describe, it, expect } from 'vitest';
import { AegisEngine } from '@aegis-kernel/core';
import { AstGrammarFuzzer } from '../src/fuzz/ast-grammar-fuzzer.js';

describe('Multi-Dialect Differential AST Semantic Grammar Fuzzer', () => {
  const engine = new AegisEngine({
    failPolicy: 'fail-closed',
    packs: ['@aegis/sql-guard', '@aegis/soc2-guard'],
  });

  it('should synthesize and evaluate 250 grammar-generated dialect expressions with 100% invariant preservation', () => {
    const summary = AstGrammarFuzzer.runDifferentialFuzz(engine, 250, 99);

    expect(summary.totalSynthesized).toBe(250);
    expect(summary.maliciousCount).toBeGreaterThan(0);
    expect(summary.benignCount).toBeGreaterThan(0);
    expect(summary.invariantPreserved).toBe(true);
    expect(summary.recall).toBe(100.0);
    expect(summary.precision).toBe(100.0);
    expect(summary.f1Score).toBe(100.0);

    // Verify all 5 dialects were exercised
    expect(summary.dialectBreakdown.POSTGRESQL.total).toBeGreaterThan(0);
    expect(summary.dialectBreakdown.MYSQL.total).toBeGreaterThan(0);
    expect(summary.dialectBreakdown.SQLITE.total).toBeGreaterThan(0);
    expect(summary.dialectBreakdown.SNOWFLAKE.total).toBeGreaterThan(0);
    expect(summary.dialectBreakdown.BIGQUERY.total).toBeGreaterThan(0);
  });
});
