import { describe, it, expect } from 'vitest';
import { SqlChecker } from '../src/checkers/sql-checker.js';
import { AegisEngine } from '../src/engine.js';

describe('SqlChecker', () => {
  const checker = new SqlChecker();

  it('should block DROP statements', () => {
    const violations = checker.evaluate(
      'SQL-002',
      'sql-guard',
      { block_statements: ['DROP', 'TRUNCATE'] },
      { tool: 'sql', params: { sql: 'DROP TABLE accounts;' } }
    );
    expect(violations.length).toBeGreaterThan(0);
    expect(violations[0].severity).toBe('critical');
  });

  it('should block TRUNCATE statements', () => {
    const violations = checker.evaluate(
      'SQL-002',
      'sql-guard',
      { block_statements: ['DROP', 'TRUNCATE'] },
      { tool: 'sql', params: { sql: 'TRUNCATE TABLE logs;' } }
    );
    expect(violations.length).toBeGreaterThan(0);
  });

  it('should block DELETE without WHERE', () => {
    const violations = checker.evaluate(
      'SQL-001',
      'sql-guard',
      { statements: ['DELETE'], require: 'WHERE_CLAUSE' },
      { tool: 'sql', params: { sql: 'DELETE FROM users' } }
    );
    expect(violations.length).toBeGreaterThan(0);
    expect(violations[0].message).toContain('WHERE');
  });

  it('should allow DELETE with valid WHERE', () => {
    const violations = checker.evaluate(
      'SQL-001',
      'sql-guard',
      { statements: ['DELETE'], require: 'WHERE_CLAUSE' },
      { tool: 'sql', params: { sql: 'DELETE FROM sessions WHERE expired = true' } }
    );
    expect(violations.length).toBe(0);
  });

  it('should use fallback regex for unparseable or dialect-specific queries', () => {
    const violations = checker.evaluate(
      'SQL-002',
      'sql-guard',
      { block_statements: ['DROP'] },
      { tool: 'sql', params: { sql: '/* strange comment */ DROP DATABASE test;' } }
    );
    expect(violations.length).toBeGreaterThan(0);
  });

  describe('AST Constant-Folding and Predicate Analysis', () => {
    const ruleParams = { statements: ['DELETE' as const], require: 'WHERE_CLAUSE' as const };

    const constantTautologies = [
      'DELETE FROM users WHERE 1=1',
      'DELETE FROM users WHERE 2 > 1',
      'DELETE FROM users WHERE NULL IS NULL',
      'DELETE FROM users WHERE 1 IN (1)',
      'DELETE FROM users WHERE 1 BETWEEN 0 AND 2',
      'DELETE FROM users WHERE id = id',
      'DELETE FROM users WHERE users.id = users.id',
      'DELETE FROM users WHERE true',
      'DELETE FROM users WHERE "a" = "a"',
      'DELETE FROM users WHERE id = 123 OR 1=1',
    ];

    for (const sql of constantTautologies) {
      it(`should block tautological mass DELETE via AST constant-folding: "${sql}"`, () => {
        const violations = checker.evaluate('SQL-001', 'sql-guard', ruleParams, {
          tool: 'sql',
          params: { sql },
        });
        expect(violations.length).toBeGreaterThan(0);
        expect(violations[0].severity).toBe('critical');
        expect(violations[0].message).toContain('tautological WHERE clause');
      });
    }

    const legitimatePredicates = [
      'DELETE FROM users WHERE id = 123',
      'DELETE FROM users WHERE id = 123 AND 1=1',
      'DELETE FROM users WHERE expires_at < NOW()',
      'DELETE FROM users WHERE status = "inactive" AND balance <= 0',
    ];

    for (const sql of legitimatePredicates) {
      it(`should allow legitimate row-restricting DELETE: "${sql}"`, () => {
        const violations = checker.evaluate('SQL-001', 'sql-guard', ruleParams, {
          tool: 'sql',
          params: { sql },
        });
        expect(violations.length).toBe(0);
      });
    }
  });
});

describe('SqlChecker regression guards (found via mutation testing)', () => {
  it('blocks SELECT result sets above the LIMIT ceiling', () => {
    const engine = new AegisEngine({ mode: 'enforce', packs: ['@aegis/sql-guard'] });
    const verdict = engine.evaluate({
      tool: 'database_exec',
      params: { query: 'SELECT * FROM users LIMIT 50000' },
    });
    expect(verdict.allowed).toBe(false);
    expect(verdict.violations.some((v) => v.ruleId === 'SQL-004')).toBe(true);
  });

  it('allows SELECTs within the LIMIT ceiling', () => {
    const engine = new AegisEngine({ mode: 'enforce', packs: ['@aegis/sql-guard'] });
    const verdict = engine.evaluate({
      tool: 'database_exec',
      params: { query: 'SELECT * FROM users LIMIT 100' },
    });
    expect(verdict.allowed).toBe(true);
  });

  it('blocks destructive SQL wrapped in a CTE via the regex fallback', () => {
    const engine = new AegisEngine({ mode: 'enforce', packs: ['@aegis/sql-guard'] });
    const verdict = engine.evaluate({
      tool: 'database_exec',
      params: { query: 'WITH cte AS (DELETE FROM users WHERE 1=1) SELECT * FROM cte' },
    });
    expect(verdict.allowed).toBe(false);
  });

  it('blocks keyword-split via string concatenation (regex fallback)', () => {
    const engine = new AegisEngine({ mode: 'enforce', packs: ['@aegis/sql-guard'] });
    const verdict = engine.evaluate({
      tool: 'database_exec',
      params: { query: "DELETE FROM users WHERE '1'||''='1'" },
    });
    expect(verdict.allowed).toBe(false);
  });
});
