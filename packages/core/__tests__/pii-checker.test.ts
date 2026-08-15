import { describe, it, expect } from 'vitest';
import { PiiChecker } from '../src/checkers/pii-checker.js';

describe('PiiChecker', () => {
  const checker = new PiiChecker();

  it('should detect and block credit cards', () => {
    const violations = checker.evaluate(
      'DATA-001',
      'data-guard',
      { patterns: ['CREDIT_CARD'], match_action: 'block' },
      { tool: 'api', params: { text: 'Card number: 4532015012345678' } }
    );
    expect(violations.length).toBe(1);
    expect(violations[0].ruleId).toBe('DATA-001');
  });

  it('should detect US SSNs', () => {
    const violations = checker.evaluate(
      'DATA-001',
      'data-guard',
      { patterns: ['US_SSN'], match_action: 'block' },
      { tool: 'api', params: { user: { ssn: '123-45-6789' } } }
    );
    expect(violations.length).toBe(1);
  });

  it('should detect OpenAI secret keys', () => {
    const violations = checker.evaluate(
      'DATA-002',
      'data-guard',
      { patterns: ['OPENAI_API_KEY'], match_action: 'block' },
      { tool: 'api', params: { auth: 'sk-proj-abc123def456ghi789jkl012mno345pqr' } }
    );
    expect(violations.length).toBe(1);
  });

  it('should detect zero-width space obfuscated sensitive credentials', () => {
    // Zero-width space (\u200B) injected into SSN
    const obfuscatedSsn = '123\u200B-45\u200B-6789';
    const violations = checker.evaluate(
      'DATA-001',
      'data-guard',
      { patterns: ['US_SSN'], match_action: 'block' },
      { tool: 'api', params: { text: obfuscatedSsn } }
    );
    expect(violations.length).toBe(1);
    expect(violations[0].ruleId).toBe('DATA-001');
  });

  it('should allow benign text without false positives', () => {
    const violations = checker.evaluate(
      'DATA-001',
      'data-guard',
      { patterns: ['CREDIT_CARD', 'US_SSN'], match_action: 'block' },
      { tool: 'api', params: { query: 'The quick brown fox jumps over the lazy dog' } }
    );
    expect(violations.length).toBe(0);
  });
});
