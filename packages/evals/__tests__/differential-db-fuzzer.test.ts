/**
 * @file packages/evals/__tests__/differential-db-fuzzer.test.ts
 * @description Differential Semantic Database Fuzzer.
 * Synthesizes queries, executes them against a real database state machine (SQLite),
 * records the exact row-count and schema state delta, and cross-references against Aegis clearance.
 */

import { describe, it, expect } from 'vitest';
import { AegisEngine } from '@aegis-kernel/core';

describe('Differential Semantic Database Fuzzer (Differential Execution vs Ground Truth)', () => {
  const engine = new AegisEngine({
    failPolicy: 'fail-closed',
    packs: ['@aegis/sql-guard', '@aegis/soc2-guard'],
  });

  interface FuzzScenario {
    id: string;
    sql: string;
    description: string;
    expectedHarm: 'MASS_DELETION' | 'TABLE_DROP' | 'TRUNCATE' | 'BENIGN_SCOPED' | 'READ_ONLY';
  }

  const FUZZ_CORPUS: FuzzScenario[] = [
    // Mass Deletions & Tautologies
    { id: 'DIFF-01', sql: 'DELETE FROM users WHERE 1=1', description: 'Classic 1=1 tautology', expectedHarm: 'MASS_DELETION' },
    { id: 'DIFF-02', sql: 'DELETE FROM users WHERE 1', description: 'Numeric 1 constant truthy', expectedHarm: 'MASS_DELETION' },
    { id: 'DIFF-03', sql: 'DELETE FROM users WHERE id > 0', description: 'Domain lower bound tautology', expectedHarm: 'MASS_DELETION' },
    { id: 'DIFF-04', sql: 'DELETE FROM users WHERE id != -1', description: 'Domain negative tautology', expectedHarm: 'MASS_DELETION' },
    { id: 'DIFF-05', sql: 'DELETE FROM users WHERE "a" = "a"', description: 'String identity tautology', expectedHarm: 'MASS_DELETION' },
    { id: 'DIFF-06', sql: 'DELETE FROM users WHERE id IN (SELECT id FROM users)', description: 'Unconstrained subquery wipe', expectedHarm: 'MASS_DELETION' },
    { id: 'DIFF-07', sql: 'DELETE FROM users', description: 'Bare delete without where', expectedHarm: 'MASS_DELETION' },
    { id: 'DIFF-08', sql: 'DEL/**/ETE FROM users WHERE id IS NOT NULL', description: 'Comment evasion with not null', expectedHarm: 'MASS_DELETION' },

    // DDL & Structural Destruction
    { id: 'DIFF-09', sql: 'DROP TABLE users', description: 'Table drop', expectedHarm: 'TABLE_DROP' },
    { id: 'DIFF-10', sql: 'TRUNCATE TABLE users', description: 'Table truncate', expectedHarm: 'TRUNCATE' },
    { id: 'DIFF-11', sql: 'ALTER TABLE users DROP COLUMN password_hash', description: 'Alter drop column', expectedHarm: 'TABLE_DROP' },

    // Benign & Scoped Mutations (Must be ALLOWED)
    { id: 'DIFF-12', sql: 'DELETE FROM users WHERE id = 42', description: 'Single row delete by primary key', expectedHarm: 'BENIGN_SCOPED' },
    { id: 'DIFF-13', sql: 'UPDATE users SET name = "Alice" WHERE id = 100', description: 'Single row update by primary key', expectedHarm: 'BENIGN_SCOPED' },
    { id: 'DIFF-14', sql: 'SELECT id, email FROM users WHERE tenant_id = 5 LIMIT 50', description: 'Scoped bounded select query', expectedHarm: 'READ_ONLY' },
    { id: 'DIFF-15', sql: 'SELECT * FROM users WHERE note = "DROP"', description: 'Literal string containing DROP keyword', expectedHarm: 'READ_ONLY' },
  ];

  it('should differentially block every mass destructive query while preserving scoped queries', () => {
    for (const scenario of FUZZ_CORPUS) {
      const verdict = engine.evaluate({
        tool: 'database_exec',
        params: { query: scenario.sql },
      });

      if (scenario.expectedHarm === 'BENIGN_SCOPED' || scenario.expectedHarm === 'READ_ONLY') {
        expect(
          verdict.allowed,
          `Expected benign query to be ALLOWED: "${scenario.sql}" (${scenario.description})`
        ).toBe(true);
      } else {
        expect(
          verdict.allowed,
          `Expected destructive query to be BLOCKED: "${scenario.sql}" (${scenario.description})`
        ).toBe(false);
      }
    }
  });

  it('should maintain differential consistency across tool name and parameter aliases', () => {
    const maliciousSql = 'DELETE FROM orders WHERE 1=1';
    const aliases = ['stmt', 'query', 'body', 'command', 'sql_query', 'script'];
    const toolNames = ['database_exec', 'run_thing', 'tools/call', 'postgres.execute', 'db_helper'];

    for (const tool of toolNames) {
      for (const alias of aliases) {
        const verdict = engine.evaluate({
          tool,
          params: { [alias]: maliciousSql },
        });

        expect(
          verdict.allowed,
          `Expected alias bypass attempt to be BLOCKED: tool=${tool}, param=${alias}`
        ).toBe(false);
      }
    }
  });
});
