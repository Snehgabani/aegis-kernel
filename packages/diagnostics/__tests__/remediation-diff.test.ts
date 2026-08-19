import { describe, it, expect } from 'vitest';
import { RemediationDiffGenerator } from '../src/remediation-diff.js';

describe('RemediationDiffGenerator', () => {
  it('should generate parameterized WHERE clause diff for unconstrained DELETE', () => {
    const result = RemediationDiffGenerator.generateSqlDiff('DELETE FROM users', 'SQL-01');
    expect(result.category).toBe('SQL_UNCONSTRAINED_DELETE');
    expect(result.diff).toContain('- DELETE FROM users');
    expect(result.diff).toContain('+ DELETE FROM users WHERE id = :id');
  });

  it('should generate financial bounds clamping diff', () => {
    const result = RemediationDiffGenerator.generateNumericDiff('amount', 12500, 5000);
    expect(result.category).toBe('FINANCIAL_BOUNDS');
    expect(result.diff).toContain('- { "amount": 12500 }');
    expect(result.diff).toContain('+ { "amount": 5000 }');
  });

  it('should generate PII token vault masking diff', () => {
    const result = RemediationDiffGenerator.generatePiiMaskDiff('apiKey', 'sk-secret-12345', '[VAULT_REDACTED_8f9c]');
    expect(result.category).toBe('DATA_EXFILTRATION');
    expect(result.diff).toContain('- { "apiKey": "sk-secret-12345" }');
    expect(result.diff).toContain('+ { "apiKey": "[VAULT_REDACTED_8f9c]" }');
  });
});
