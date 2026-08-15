import { describe, it, expect } from 'vitest';
import { CustomChecker } from '../src/checkers/custom-checker.js';
import type { ToolCall } from '../src/types.js';

describe('CustomChecker (Zero-Eval Declarative DSL)', () => {
  const checker = new CustomChecker();

  it('should block when declarative numeric and equality conditions match', () => {
    const toolCall: ToolCall = {
      tool: 'payout',
      params: { amount: 6000, currency: 'EUR' },
    };

    const violations = checker.evaluate(
      'RULE-DSL-1',
      'test-pack',
      { predicate: "params.amount > 5000 && params.currency != 'USD'" },
      toolCall
    );

    expect(violations.length).toBe(1);
    expect(violations[0].ruleId).toBe('RULE-DSL-1');
  });

  it('should evaluate "in" array inclusion predicates safely', () => {
    const toolCall: ToolCall = {
      tool: 'grant_access',
      params: { role: 'guest' },
    };

    const violations = checker.evaluate(
      'RULE-DSL-2',
      'test-pack',
      { predicate: "params.role in ['guest', 'anonymous']" },
      toolCall
    );

    expect(violations.length).toBe(1);
  });

  it('should be completely immune to prototype-chain walk injection payloads', () => {
    const toolCall: ToolCall = {
      tool: 'eval_test',
      params: { flag: true },
    };

    // Attempted sandbox escape payload
    const maliciousPredicate =
      "this.constructor.constructor('return process')().mainModule.require('child_process')";

    // Zero-eval AST parser evaluates path, does not execute code, and returns false/warning
    const violations = checker.evaluate(
      'RULE-ESCAPE-1',
      'test-pack',
      { predicate: maliciousPredicate },
      toolCall
    );

    // Host runtime remains unpolluted and untouched
    expect((Object.prototype as any).polluted).toBeUndefined();
    expect(violations.length).toBe(0);
  });
});
