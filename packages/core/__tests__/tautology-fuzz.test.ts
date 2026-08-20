/**
 * @file packages/core/__tests__/tautology-fuzz.test.ts
 * @description Property-based fuzz tests for SQL tautology detection
 *
 * Generates random SQL tautologies and verifies that Aegis blocks them all,
 * while legitimate queries are allowed. Uses repeated random sampling
 * (200 iterations per property) for broad coverage.
 *
 * NOTE: These tests use Math.random() for simplicity. A full property-based
 * approach using fast-check's fc.assert/fc.property with shrinking and
 * reproducible seeds is tracked in ROADMAP.md.
 */

import { describe, it, expect } from 'vitest';
import { SqlChecker } from '../src/checkers/sql-checker.js';

const checker = new SqlChecker();

// ── Property: All constant-tautology WHERE clauses are blocked ──────────

/**
 * A constant-tautology WHERE clause is one that is TRUE for every row.
 * Examples: 1=1, 2>1, 'a'='a', TRUE, 1, id>0, id IS NOT NULL
 *
 * Property: For any SQL DELETE with a constant-tautology WHERE,
 *          SqlChecker MUST return at least one violation.
 */
describe('Property: Constant-tautology WHERE clauses are always blocked', () => {
  const tautologyGenerators = {
    numericIdentity: () => {
      const n = Math.floor(Math.random() * 1000);
      return `${n} = ${n}`;
    },
    numericComparison: () => {
      const a = Math.floor(Math.random() * 100) + 1;
      const b = Math.floor(Math.random() * a);
      return `${a} > ${b}`;
    },
    stringIdentity: () => {
      const s = Math.random().toString(36).substring(2, 8);
      return `'${s}' = '${s}'`;
    },
    selfColumn: () => {
      const cols = ['id', 'user_id', 'account_id', 'status', 'type', 'role'];
      const col = cols[Math.floor(Math.random() * cols.length)];
      return `${col} = ${col}`;
    },
    isNotNull: () => {
      const cols = ['id', 'email', 'name', 'created_at', 'deleted_at'];
      const col = cols[Math.floor(Math.random() * cols.length)];
      return `${col} IS NOT NULL`;
    },
    orTautology: () => {
      const id = Math.floor(Math.random() * 100) + 1;
      const tauts = ['1=1', '2>1', 'TRUE', "'a'='a'"];
      const t = tauts[Math.floor(Math.random() * tauts.length)];
      return `id = ${id} OR ${t}`;
    },
    unconstrainedSubquery: () => 'id IN (SELECT id FROM users)',
  };

  const generators = Object.values(tautologyGenerators);

  it('should block ALL generated tautological WHERE clauses on DELETE', () => {
    for (let run = 0; run < 200; run++) {
      const gen = generators[Math.floor(Math.random() * generators.length)];
      const whereClause = gen();
      const sql = `DELETE FROM users WHERE ${whereClause}`;
      const violations = checker.evaluate(
        'SQL-FUZZ-001',
        'sql-guard',
        { statements: ['DELETE'], require: 'WHERE_CLAUSE' },
        { tool: 'sql', params: { sql } },
      );
      expect(violations.length).toBeGreaterThan(0);
    }
  });
});

// ── Property: All legitimate ID-specific WHERE clauses are allowed ─────

describe('Property: Legitimate targeted WHERE clauses are always allowed', () => {
  const validWhereGenerators = {
    numericEquality: () => {
      const id = Math.floor(Math.random() * 10000) + 1;
      return `id = ${id}`;
    },
    stringEquality: () => {
      const statuses = ['active', 'inactive', 'pending', 'archived', 'deleted'];
      return `status = '${statuses[Math.floor(Math.random() * statuses.length)]}'`;
    },
    compoundCondition: () => {
      const id = Math.floor(Math.random() * 10000) + 1;
      const statuses = ['active', 'inactive', 'pending'];
      return `user_id = ${id} AND status = '${statuses[Math.floor(Math.random() * statuses.length)]}'`;
    },
    dateRange: () => {
      const start = new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString();
      const end = new Date(Date.now() + Math.random() * 365 * 24 * 60 * 60 * 1000).toISOString();
      return `created_at BETWEEN '${start}' AND '${end}'`;
    },
    inClause: () => {
      const count = Math.floor(Math.random() * 10) + 1;
      const ids = Array.from({ length: count }, () => Math.floor(Math.random() * 100) + 1);
      return `id IN (${ids.join(', ')})`;
    },
    idGt: () => {
      const id = Math.floor(Math.random() * 1000) + 1;
      return `id > ${id} AND id < ${id + 100}`;
    },
  };

  const generators = Object.values(validWhereGenerators);

  it('should ALLOW all legitimate targeted WHERE clauses on DELETE', () => {
    for (let run = 0; run < 200; run++) {
      const gen = generators[Math.floor(Math.random() * generators.length)];
      const whereClause = gen();
      const sql = `DELETE FROM users WHERE ${whereClause}`;
      const violations = checker.evaluate(
        'SQL-FUZZ-002',
        'sql-guard',
        { statements: ['DELETE'], require: 'WHERE_CLAUSE' },
        { tool: 'sql', params: { sql } },
      );
      expect(violations.length).toBe(0);
    }
  });
});

// ── Property: DDL statements are always blocked regardless of variation ──

describe('Property: DDL statements are always blocked', () => {
  const ddlVariations = [
    'DROP TABLE users',
    'TRUNCATE TABLE logs',
    'ALTER TABLE users DROP COLUMN email',
    'GRANT ALL PRIVILEGES ON *.* TO test',
    'REVOKE ALL ON users FROM test',
  ];

  it('should block all DDL statement variations', () => {
    for (const sql of ddlVariations) {
      const violations = checker.evaluate(
        'SQL-FUZZ-003',
        'sql-guard',
        { block_statements: ['DROP', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE'] },
        { tool: 'sql', params: { sql } },
      );
      expect(violations.length).toBeGreaterThan(0);
    }
  });
});