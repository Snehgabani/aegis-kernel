/**
 * @file packages/core/__tests__/tautology-fuzz.test.ts
 * @description Deterministic property-based fuzz tests for SQL tautology detection using fast-check
 *
 * Generates arbitrary SQL tautologies with reproducible seed (seed: 42),
 * automatic test-case shrinking, and verifies that Aegis blocks destructive
 * queries while legitimate targeted updates and deletions pass through cleanly.
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { SqlChecker } from '../src/checkers/sql-checker.js';

const checker = new SqlChecker();

describe('Property-Based SQL Fuzzing Matrix (Deterministic fast-check, seed: 42)', () => {
  // Arbitrary generator for SQL column identifiers
  const columnArb = fc.constantFrom('id', 'user_id', 'account_id', 'status', 'type', 'role', 'email', 'created_at');

  // Arbitrary generator for tautological WHERE clauses
  const tautologyWhereArb = fc.oneof(
    fc.integer({ min: 0, max: 999999 }).map((n) => `${n} = ${n}`),
    fc.tuple(fc.integer({ min: 2, max: 100 }), fc.integer({ min: 1, max: 99 })).map(([a, b]) => `${Math.max(a, b)} > ${Math.min(a, b)}`),
    fc.string({ minLength: 1, maxLength: 12 }).map((s) => `'${s.replace(/'/g, "''")}' = '${s.replace(/'/g, "''")}'`),
    columnArb.map((col) => `${col} = ${col}`),
    columnArb.map((col) => `${col} IS NOT NULL`),
    fc.tuple(fc.integer({ min: 1, max: 1000 }), fc.constantFrom('1=1', '2>1', 'TRUE', "'a'='a'")).map(
      ([id, taut]) => `id = ${id} OR ${taut}`
    ),
    fc.constant('id IN (SELECT id FROM users)')
  );

  // Arbitrary generator for legitimate, targeted WHERE clauses
  const validWhereArb = fc.oneof(
    fc.integer({ min: 1, max: 100000 }).map((id) => `id = ${id}`),
    fc.constantFrom('active', 'inactive', 'pending', 'archived').map((st) => `status = '${st}'`),
    fc.tuple(fc.integer({ min: 1, max: 10000 }), fc.constantFrom('active', 'pending')).map(
      ([id, st]) => `user_id = ${id} AND status = '${st}'`
    ),
    fc.array(fc.integer({ min: 1, max: 1000 }), { minLength: 1, maxLength: 5 }).map(
      (ids) => `id IN (${ids.join(', ')})`
    ),
    fc.integer({ min: 1, max: 1000 }).map((id) => `id > ${id} AND id < ${id + 50}`)
  );

  it('Property 1: should block ALL generated tautological WHERE clauses on DELETE', () => {
    fc.assert(
      fc.property(tautologyWhereArb, (whereClause) => {
        const sql = `DELETE FROM users WHERE ${whereClause}`;
        const violations = checker.evaluate(
          'SQL-FUZZ-001',
          'sql-guard',
          { statements: ['DELETE'], require: 'WHERE_CLAUSE' },
          { tool: 'sql', params: { sql } },
        );
        return violations.length > 0;
      }),
      { numRuns: 200, seed: 42 }
    );
  });

  it('Property 2: should block ALL generated tautological WHERE clauses on UPDATE', () => {
    fc.assert(
      fc.property(tautologyWhereArb, (whereClause) => {
        const sql = `UPDATE users SET status = 'disabled' WHERE ${whereClause}`;
        const violations = checker.evaluate(
          'SQL-FUZZ-002',
          'sql-guard',
          { statements: ['UPDATE'], require: 'WHERE_CLAUSE' },
          { tool: 'sql', params: { sql } },
        );
        return violations.length > 0;
      }),
      { numRuns: 200, seed: 42 }
    );
  });

  it('Property 3: should ALLOW all legitimate targeted WHERE clauses on DELETE & UPDATE', () => {
    fc.assert(
      fc.property(validWhereArb, (whereClause) => {
        const deleteSql = `DELETE FROM users WHERE ${whereClause}`;
        const updateSql = `UPDATE accounts SET balance = 0 WHERE ${whereClause}`;

        const delViolations = checker.evaluate(
          'SQL-FUZZ-003',
          'sql-guard',
          { statements: ['DELETE'], require: 'WHERE_CLAUSE' },
          { tool: 'sql', params: { sql: deleteSql } },
        );
        const updViolations = checker.evaluate(
          'SQL-FUZZ-004',
          'sql-guard',
          { statements: ['UPDATE'], require: 'WHERE_CLAUSE' },
          { tool: 'sql', params: { sql: updateSql } },
        );

        return delViolations.length === 0 && updViolations.length === 0;
      }),
      { numRuns: 200, seed: 42 }
    );
  });

  it('Property 4: should block all DDL and schema destruction statement variations', () => {
    const ddlVariations = [
      'DROP TABLE users',
      'DROP DATABASE production',
      'TRUNCATE TABLE audit_logs',
      'ALTER TABLE users DROP COLUMN password_hash',
      'GRANT ALL PRIVILEGES ON *.* TO hacker@localhost',
      'REVOKE ALL ON users FROM admin',
    ];

    for (const sql of ddlVariations) {
      const violations = checker.evaluate(
        'SQL-FUZZ-005',
        'sql-guard',
        { block_statements: ['DROP', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE'] },
        { tool: 'sql', params: { sql } },
      );
      expect(violations.length).toBeGreaterThan(0);
    }
  });
});