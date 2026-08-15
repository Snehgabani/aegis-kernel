import { describe, it, expect, beforeEach } from 'vitest';
import { PiiTokenVault } from '../src/pii/token-vault.js';

describe('PiiTokenVault', () => {
  let vault: PiiTokenVault;

  beforeEach(() => {
    vault = new PiiTokenVault();
  });

  it('should tokenize and detokenize PII', () => {
    const text = 'My email is test@example.com and ssn is 123-45-6789.';
    const vaultWithCustom = new PiiTokenVault({
      patterns: {
        EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
        SSN: /\b\d{3}-\d{2}-\d{4}\b/
      }
    });

    const tokenized = vaultWithCustom.tokenize(text);
    expect(tokenized.sanitized).not.toContain('test@example.com');
    expect(tokenized.sanitized).not.toContain('123-45-6789');
    expect(tokenized.tokensCreated).toBe(2);
    expect(tokenized.tokenTypes.EMAIL).toBe(1);
    expect(tokenized.tokenTypes.SSN).toBe(1);

    const detokenized = vaultWithCustom.detokenize(tokenized.sanitized);
    expect(detokenized.restored).toBe(text);
    expect(detokenized.tokensRestored).toBe(2);
  });

  it('should reuse tokens for same PII', () => {
    const text = 'Call 123-45-6789 and fax 123-45-6789.';
    const vaultWithCustom = new PiiTokenVault({
      patterns: {
        SSN: /\b\d{3}-\d{2}-\d{4}\b/
      }
    });

    const tokenized = vaultWithCustom.tokenize(text);
    expect(tokenized.tokensCreated).toBe(1);
    
    const tokenRegex = /<SSN_[a-f0-9]+>/g;
    const matches = tokenized.sanitized.match(tokenRegex);
    expect(matches?.length).toBe(2);
    expect(matches?.[0]).toBe(matches?.[1]);
  });

  it('should clear vault', () => {
    const text = 'My ssn is 123-45-6789.';
    const vaultWithCustom = new PiiTokenVault({
      patterns: { SSN: /\b\d{3}-\d{2}-\d{4}\b/ }
    });

    const tokenized = vaultWithCustom.tokenize(text);
    expect(vaultWithCustom.getVaultSize()).toBe(1);

    vaultWithCustom.clear();
    expect(vaultWithCustom.getVaultSize()).toBe(0);

    const detokenized = vaultWithCustom.detokenize(tokenized.sanitized);
    expect(detokenized.restored).toBe(tokenized.sanitized); 
  });
  
  it('should handle multiple PII types', () => {
      const text = 'email test@example.com ssn 123-45-6789';
      const myVault = new PiiTokenVault({
          patterns: {
              EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
              SSN: /\b\d{3}-\d{2}-\d{4}\b/
          }
      });
      const t = myVault.tokenize(text);
      expect(t.tokensCreated).toBe(2);
      expect(myVault.detokenize(t.sanitized).restored).toBe(text);
  });
  
  it('should handle nested/already tokenized text', () => {
      const myVault = new PiiTokenVault({
          patterns: { SSN: /\b\d{3}-\d{2}-\d{4}\b/ }
      });
      const t = myVault.tokenize("123-45-6789");
      const t2 = myVault.tokenize(t.sanitized);
      expect(t2.sanitized).toBe(t.sanitized);
      expect(t2.tokensCreated).toBe(0);
      expect(myVault.detokenize(t2.sanitized).restored).toBe("123-45-6789");
  });
  
  it('should handle empty string gracefully', () => {
      const v = new PiiTokenVault();
      expect(v.tokenize('').sanitized).toBe('');
      expect(v.detokenize('').restored).toBe('');
  });
});
