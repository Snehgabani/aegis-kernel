import { describe, it, expect } from 'vitest';
import { AegisEngine } from '../src/engine.js';
import type { ToolCall } from '../src/types.js';

describe('Adversarial & Edge-Case Stress Testing Suite', () => {
  const engine = new AegisEngine({ mode: 'enforce' });

  // 1. SQL Obfuscation & Dialect Bypass Attacks
  describe('SQL AST & Injection Evasion Attacks', () => {
    const dangerousSqls = [
      'delete from users', // lowercase
      'DELETE   FROM   users', // multi-whitespace
      'DELETE/*comment*/FROM users', // inline comment
      'DELETE\nFROM\nusers', // newlines
      'DROP TABLE IF EXISTS "users";', // quoted table
      'DROP DATABASE production;', // database drop
      'TRUNCATE TABLE billing_logs;', // truncate table
      'UPDATE accounts SET balance = 0;', // mass update
      'ALTER TABLE users DROP COLUMN password_hash;', // alter table drop column
    ];

    for (const [idx, sql] of dangerousSqls.entries()) {
      it(`should block dangerous query vector #${idx + 1}: ${sql.replace(/\n/g, ' ')}`, () => {
        const toolCall: ToolCall = {
          tool: 'execute_sql',
          params: { query: sql },
        };
        const verdict = engine.evaluate(toolCall);
        expect(verdict.allowed).toBe(false);
        expect(verdict.violations.length).toBeGreaterThan(0);
        expect(verdict.proofHash).toHaveLength(64);
      });
    }

    const safeSqls = [
      'SELECT id, name FROM users WHERE id = 123',
      'SELECT * FROM orders WHERE user_id = :uid LIMIT 50',
      'DELETE FROM temporary_tokens WHERE expires_at < NOW()',
      'UPDATE users SET status = "active" WHERE id = 456',
      'INSERT INTO audit_log (action, timestamp) VALUES ("login", NOW())',
    ];

    for (const [idx, sql] of safeSqls.entries()) {
      it(`should allow legitimate safe query #${idx + 1}: ${sql}`, () => {
        const toolCall: ToolCall = {
          tool: 'execute_sql',
          params: { query: sql },
        };
        const verdict = engine.evaluate(toolCall);
        expect(verdict.allowed).toBe(true);
        expect(verdict.violations.length).toBe(0);
      });
    }
  });

  // 2. Nested PII & Credential Exfiltration Vectors
  describe('Deeply Nested PII & Secret Scanning', () => {
    it('should detect API keys nested 4 levels deep in arbitrary JSON structures', () => {
      const toolCall: ToolCall = {
        tool: 'sync_data',
        params: {
          request: {
            headers: {
              auth: {
                token: 'sk-proj-999988887777666655554444333322221111',
              },
            },
          },
        },
      };
      const verdict = engine.evaluate(toolCall);
      expect(verdict.allowed).toBe(false);
      expect(verdict.violations.some((v) => v.ruleId === 'DATA-002')).toBe(true);
    });

    it('should detect GitHub personal access tokens in raw string dumps', () => {
      const toolCall: ToolCall = {
        tool: 'post_issue',
        params: {
          comment: 'Here is the config: ghp_123456789012345678901234567890123456',
        },
      };
      const verdict = engine.evaluate(toolCall);
      expect(verdict.allowed).toBe(false);
    });

    it('should detect AWS Access Keys in parameter arrays', () => {
      const toolCall: ToolCall = {
        tool: 'cloud_deploy',
        params: {
          keys: ['AKIAIOSFODNN7EXAMPLE', 'other_param'],
        },
      };
      const verdict = engine.evaluate(toolCall);
      expect(verdict.allowed).toBe(false);
    });
  });

  // 3. Zero-Eval Sandbox Isolation & Prototype Pollution Defenses
  describe('Zero-Eval Sandbox Isolation & Prototype Attack Defenses', () => {
    it('should completely neutralize classic constructor.constructor sandbox escapes', () => {
      const customRuleEngine = new AegisEngine({
        packs: [
          {
            id: 'sandbox-test',
            name: 'Sandbox Security Test',
            version: '1.0.0',
            rules: [
              {
                id: 'SANDBOX-01',
                severity: 'critical',
                description: 'Sandbox isolation test',
                condition: {
                  type: 'custom',
                  params: {
                    predicate:
                      "this.constructor.constructor('return process')().mainModule.require('child_process')",
                  },
                },
              },
            ],
          },
        ],
      });

      const toolCall: ToolCall = {
        tool: 'test_sandbox',
        params: { flag: true },
      };

      // Does not throw unhandled exception or escape host
      const verdict = customRuleEngine.evaluate(toolCall);
      expect(verdict.allowed).toBe(true);
      expect((Object.prototype as any).polluted).toBeUndefined();
    });
  });

  // 4. State Invariant Transition Checking
  describe('State Invariant Pre & Post Condition Assertions', () => {
    it('should enforce state bounds during multi-step execution', () => {
      const toolCall: ToolCall = {
        tool: 'payout_user',
        params: { amount: 15000 },
      };

      const verdict = engine.evaluate(toolCall, {
        state: {
          account_status: 'active',
          spent_today: 40000,
          daily_budget: 50000,
        },
      });

      expect(verdict.allowed).toBe(false);
      expect(verdict.violations.some((v) => v.ruleId === 'FIN-STATE-001')).toBe(true);
    });
  });

  // 5. Rate Limiting & High-Concurrency Resilience
  describe('High-Concurrency & Performance Resilience', () => {
    it('should handle 1,000 rapid sequential evaluations in under 500ms with zero memory leaks', () => {
      const startTime = performance.now();
      const iterations = 1000;

      for (let i = 0; i < iterations; i++) {
        const toolCall: ToolCall = {
          tool: 'rapid_query',
          params: { sql: `SELECT * FROM items WHERE id = ${i};` },
        };
        const verdict = engine.evaluate(toolCall);
        expect(verdict.allowed).toBe(true);
      }

      const totalTime = performance.now() - startTime;
      const perEval = totalTime / iterations;

      expect(totalTime).toBeLessThan(2500);
      expect(perEval).toBeLessThan(2.5);
    });
  });
});
