import { describe, it, expect } from 'vitest';
import { NumericChecker } from '../src/checkers/numeric-checker.js';

describe('NumericChecker', () => {
  it('should enforce maximum numeric boundary', () => {
    const checker = new NumericChecker();
    const violations = checker.evaluate(
      'FIN-001',
      'finance-guard',
      { field: 'amount', max: 1000 },
      { tool: 'transfer', params: { amount: 5000 } }
    );
    expect(violations.length).toBe(1);
    expect(violations[0].severity).toBe('critical');
  });

  it('should enforce minimum numeric boundary', () => {
    const checker = new NumericChecker();
    const violations = checker.evaluate(
      'BOUND-01',
      'custom',
      { field: 'quantity', min: 1 },
      { tool: 'order', params: { quantity: 0 } }
    );
    expect(violations.length).toBe(1);
  });

  it('should allow values within bounds', () => {
    const checker = new NumericChecker();
    const violations = checker.evaluate(
      'FIN-001',
      'finance-guard',
      { field: 'amount', min: 1, max: 1000 },
      { tool: 'transfer', params: { amount: 500 } }
    );
    expect(violations.length).toBe(0);
  });

  it('should enforce sliding window rate limit', () => {
    const checker = new NumericChecker();
    const condition = { field: 'amount', rate_limit: { max_per_minute: 3 } };

    // Fire 3 times
    checker.evaluate('FIN-RATE', 'finance', condition, { tool: 'payout', params: { amount: 10 } });
    checker.evaluate('FIN-RATE', 'finance', condition, { tool: 'payout', params: { amount: 10 } });
    checker.evaluate('FIN-RATE', 'finance', condition, { tool: 'payout', params: { amount: 10 } });

    // 4th time should trigger rate limit violation
    const violations = checker.evaluate('FIN-RATE', 'finance', condition, { tool: 'payout', params: { amount: 10 } });
    expect(violations.length).toBe(1);
    expect(violations[0].message).toContain('Rate limit');
  });
});

describe('NumericChecker rate-limit boundary (found via mutation testing)', () => {
  it('allows exactly max_per_minute invocations, blocks the next one', () => {
    const checker = new NumericChecker();
    const params = { field: 'amount', rate_limit: { max_per_minute: 1 } };
    const call = { tool: 'payout', params: { amount: 100 } };

    const first = checker.evaluate('FIN-RL', 'finance-guard', params, call);
    expect(first.length).toBe(0); // 1st call within limit

    const second = checker.evaluate('FIN-RL', 'finance-guard', params, call);
    expect(second.length).toBe(1); // 2nd call exceeds limit
    expect(second[0].severity).toBe('critical');
  });
});
