import { describe, it, expect, beforeEach } from 'vitest';
import {
  ValidatorRegistry,
  BannedCompetitorsValidator,
  ToxicityKeywordsValidator,
  UrlSafetyValidator,
  CodeInjectionValidator,
  CommunityValidator,
  ValidatorVerdict
} from '../src/hub/validator-hub';

describe('Validator Hub', () => {
  let registry: ValidatorRegistry;

  beforeEach(() => {
    registry = new ValidatorRegistry();
  });

  it('should register built-in validators on initialization', () => {
    const validators = registry.list();
    expect(validators.length).toBeGreaterThanOrEqual(4);
    
    expect(registry.get('community.banned-competitors')).toBeInstanceOf(BannedCompetitorsValidator);
    expect(registry.get('community.toxicity-keywords')).toBeInstanceOf(ToxicityKeywordsValidator);
    expect(registry.get('community.url-safety')).toBeInstanceOf(UrlSafetyValidator);
    expect(registry.get('community.code-injection')).toBeInstanceOf(CodeInjectionValidator);
  });

  it('should allow registering a new custom validator', () => {
    const customValidator: CommunityValidator = {
      id: 'custom.test',
      description: 'Test',
      validate: (input) => ({ passed: true, score: 0, reason: 'ok' })
    };
    registry.register(customValidator);
    expect(registry.get('custom.test')).toBe(customValidator);
  });

  describe('BannedCompetitorsValidator', () => {
    it('should fail when competitor is mentioned', () => {
      const validator = new BannedCompetitorsValidator();
      const result = validator.validate('We are better than Evil_Corp!');
      expect(result.passed).toBe(false);
      expect(result.score).toBe(1.0);
    });

    it('should pass when no competitor is mentioned', () => {
      const validator = new BannedCompetitorsValidator();
      const result = validator.validate('We are the best company in the world!');
      expect(result.passed).toBe(true);
      expect(result.score).toBe(0.0);
    });
  });

  describe('ToxicityKeywordsValidator', () => {
    it('should fail when toxic word is present', () => {
      const validator = new ToxicityKeywordsValidator();
      const result = validator.validate('This is a TOXIC_word!');
      expect(result.passed).toBe(false);
      expect(result.score).toBeGreaterThan(0);
    });
  });

  describe('UrlSafetyValidator', () => {
    it('should fail when malware domain is present', () => {
      const validator = new UrlSafetyValidator();
      const result = validator.validate('Visit http://malware.com/download');
      expect(result.passed).toBe(false);
    });
  });

  describe('CodeInjectionValidator', () => {
    it('should fail when code injection pattern is matched', () => {
      const validator = new CodeInjectionValidator();
      const result = validator.validate('Please run eval("alert(1)")');
      expect(result.passed).toBe(false);
    });
  });
});
