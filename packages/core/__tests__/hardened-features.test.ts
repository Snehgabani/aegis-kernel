import { describe, expect, it } from 'vitest';
import { CustomChecker } from '../src/checkers/custom-checker.js';
import { NumericChecker } from '../src/checkers/numeric-checker.js';
import { PiiChecker } from '../src/checkers/pii-checker.js';
import { SqlChecker } from '../src/checkers/sql-checker.js';
import { AegisEngine } from '../src/engine.js';

describe('Hardened Enterprise Capabilities & Dialect Evasion Defense', () => {
  describe('Multi-Dialect & CTE SQL Invariant Enforcement', () => {
    const sqlChecker = new SqlChecker();

    it('should detect mutating CTE with hidden DELETE inside WITH statement', () => {
      const sql = 'WITH deleted_rows AS (DELETE FROM audit_logs WHERE id = 1 RETURNING *) SELECT * FROM deleted_rows;';
      const violations = sqlChecker.evaluate(
        'SQL-CTE-001',
        'sql-guard',
        { block_statements: ['DELETE'] },
        { tool: 'sql_exec', params: { query: sql } }
      );

      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].severity).toBe('critical');
      expect(violations[0].message).toContain('DELETE');
    });

    it('should strip quotes safely and parse PostgreSQL / SQLite syntax without syntax crashing', () => {
      const pgSql = "SELECT id, name FROM users WHERE metadata->>'role' = 'admin' LIMIT 10;";
      const violations = sqlChecker.evaluate(
        'SQL-PG-001',
        'sql-guard',
        { max_limit: 50 },
        { tool: 'sql_exec', params: { query: pgSql } }
      );

      expect(violations.length).toBe(0);
    });

    it('should normalize and block SQL with comments injected across multiple keyword segments', () => {
      const evasiveSql = 'D/*c1*/E/*c2*/L/*c3*/E/*c4*/T/*c5*/E FROM transactions;';
      const violations = sqlChecker.evaluate(
        'SQL-EVADE-001',
        'sql-guard',
        { require: 'WHERE_CLAUSE' },
        { tool: 'sql_exec', params: { query: evasiveSql } }
      );

      expect(violations.length).toBeGreaterThan(0);
      expect(violations[0].severity).toBe('critical');
    });
  });

  describe('Robust Numeric Bounds, Formatted Strings, and BigInt Support', () => {
    const numericChecker = new NumericChecker();

    it('should parse and enforce limits on currency-formatted strings ($5,000.00, €12,500)', () => {
      const violations = numericChecker.evaluate(
        'FIN-001',
        'finance-guard',
        { field: 'amount', max: 10000 },
        { tool: 'payout', params: { amount: '$12,500.00' } }
      );

      expect(violations.length).toBe(1);
      expect(violations[0].severity).toBe('critical');
      expect(violations[0].message).toContain('exceeds maximum allowed limit');
    });

    it('should permit valid formatted currency within bounds ($2,500.50)', () => {
      const violations = numericChecker.evaluate(
        'FIN-001',
        'finance-guard',
        { field: 'amount', max: 10000 },
        { tool: 'payout', params: { amount: '$2,500.50' } }
      );

      expect(violations.length).toBe(0);
    });

    it('should explicitly reject NaN and Infinity with a critical violation', () => {
      const nanViolations = numericChecker.evaluate(
        'FIN-001',
        'finance-guard',
        { field: 'amount', max: 10000 },
        { tool: 'payout', params: { amount: NaN } }
      );
      expect(nanViolations.length).toBe(1);
      expect(nanViolations[0].message).toContain('unparseable non-numeric value');

      const infViolations = numericChecker.evaluate(
        'FIN-001',
        'finance-guard',
        { field: 'amount', max: 10000 },
        { tool: 'payout', params: { amount: Infinity } }
      );
      expect(infViolations.length).toBe(1);
      expect(infViolations[0].message).toContain('unparseable non-numeric value');
    });

    it('should handle BigInt values cleanly without serialization crashing', () => {
      const violations = numericChecker.evaluate(
        'FIN-001',
        'finance-guard',
        { field: 'amount', max: 10000 },
        { tool: 'payout', params: { amount: BigInt(5000) } }
      );

      expect(violations.length).toBe(0);
    });
  });

  describe('Comprehensive PII, Cloud Secrets, and Global Identifier Detection', () => {
    const piiChecker = new PiiChecker();

    it('should detect delimited credit card numbers with spaces and hyphens', () => {
      const violations = piiChecker.evaluate(
        'PCI-001',
        'pci-dss-guard',
        { patterns: ['CREDIT_CARD'] },
        { tool: 'log_payment', params: { card: '4111-2222-3333-4444' } }
      );

      expect(violations.length).toBe(1);
      expect(violations[0].severity).toBe('critical');
    });

    it('should detect JSON Web Tokens (JWT)', () => {
      const sampleJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature12345';
      const violations = piiChecker.evaluate(
        'SEC-001',
        'data-guard',
        { patterns: ['JWT_TOKEN'] },
        { tool: 'send_webhook', params: { auth_header: `Bearer ${sampleJwt}` } }
      );

      expect(violations.length).toBe(1);
    });

    it('should detect GCP Service Account JSON keys', () => {
      const gcpKey = JSON.stringify({
        type: 'service_account',
        project_id: 'aegis-cloud-prod',
        private_key_id: 'abcd1234efgh',
      });
      const violations = piiChecker.evaluate(
        'SEC-002',
        'data-guard',
        { patterns: ['GCP_SERVICE_ACCOUNT'] },
        { tool: 'deploy_service', params: { service_account: gcpKey } }
      );

      expect(violations.length).toBe(1);
    });

    it('should detect Database Connection URI credentials', () => {
      const dbUri = 'postgresql://admin:SuperSecretPass123@db.internal.net:5432/production';
      const violations = piiChecker.evaluate(
        'SEC-003',
        'data-guard',
        { patterns: ['DATABASE_URI_SECRET'] },
        { tool: 'connect_db', params: { dsn: dbUri } }
      );

      expect(violations.length).toBe(1);
    });

    it('should detect International IBAN bank identifiers', () => {
      const iban = 'GB29 NWBK 6016 1331 9268 19';
      const violations = piiChecker.evaluate(
        'GDPR-001',
        'data-guard',
        { patterns: ['IBAN'] },
        { tool: 'payout_wire', params: { account: iban } }
      );

      expect(violations.length).toBe(1);
    });
  });

  describe('Safe Custom DSL Parser with Nested Parentheses & Strict Equality', () => {
    const customChecker = new CustomChecker();

    it('should correctly parse nested outer parentheses and logical combinations', () => {
      const expr = '((params.tier === "enterprise") || (params.tier === "pro")) && (params.active === true)';
      
      expect(
        customChecker.evaluateExpression(expr, { params: { tier: 'enterprise', active: true } })
      ).toBe(true);

      expect(
        customChecker.evaluateExpression(expr, { params: { tier: 'free', active: true } })
      ).toBe(false);

      expect(
        customChecker.evaluateExpression(expr, { params: { tier: 'pro', active: false } })
      ).toBe(false);
    });

    it('should enforce strict equality (===) correctly', () => {
      expect(
        customChecker.evaluateExpression('params.count === 0', { params: { count: 0 } })
      ).toBe(true);

      // In strict equality, string "0" is not equal to number 0
      expect(
        customChecker.evaluateExpression('params.count === 0', { params: { count: '0' } })
      ).toBe(false);
    });

    it('should compute arithmetic precedence correctly (multiplication before addition)', () => {
      expect(
        customChecker.evaluateExpression('params.base + params.fee * 2 <= 50', {
          params: { base: 10, fee: 20 }, // 10 + (20 * 2) = 50 <= 50 -> true
        })
      ).toBe(true);

      expect(
        customChecker.evaluateExpression('params.base + params.fee * 2 <= 50', {
          params: { base: 20, fee: 20 }, // 20 + (20 * 2) = 60 <= 50 -> false
        })
      ).toBe(false);
    });
  });

  describe('Fail-Closed Enterprise Security Mode & Async State Providers', () => {
    it('should support async state providers in evaluateAsync', async () => {
      const engine = new AegisEngine({
        packs: ['@aegis/finance-guard'],
        stateProvider: async (toolCall) => {
          // Simulate fetching trusted ledger state from Redis/Postgres
          if (toolCall.tool === 'payout') {
            return { account_status: 'active', spent_today: 400, daily_budget: 1000 };
          }
          return {};
        },
      });

      // Allowed because 400 + 500 <= 1000
      const validVerdict = await engine.evaluateAsync({
        tool: 'payout',
        params: { amount: 500 },
      });
      expect(validVerdict.allowed).toBe(true);

      // Blocked because 400 + 700 = 1100 > 1000
      const invalidVerdict = await engine.evaluateAsync({
        tool: 'payout',
        params: { amount: 700 },
      });
      expect(invalidVerdict.allowed).toBe(false);
      expect(invalidVerdict.violations[0].ruleId).toBe('FIN-STATE-001');
    });
  });
});
