export interface ValidatorVerdict {
  passed: boolean;
  score: number; // 0.0 to 1.0
  reason: string;
  metadata?: Record<string, any>;
}

export interface ValidatorProtocol {
  id: string;
  description: string;
  validate(input: string, context?: Record<string, any>): Promise<ValidatorVerdict> | ValidatorVerdict;
}

export type CommunityValidator = ValidatorProtocol;

export class ValidatorRegistry {
  private validators: Map<string, CommunityValidator> = new Map();

  constructor() {
    this.registerBuiltIns();
  }

  public register(validator: CommunityValidator): void {
    if (this.validators.has(validator.id)) {
      console.warn(`Validator ${validator.id} is already registered. Overwriting.`);
    }
    this.validators.set(validator.id, validator);
  }

  public get(id: string): CommunityValidator | undefined {
    return this.validators.get(id);
  }

  public list(): CommunityValidator[] {
    return Array.from(this.validators.values());
  }

  public async loadDynamic(validatorPath: string): Promise<void> {
    try {
      const module = await import(validatorPath);
      if (module.default && typeof module.default.id === 'string' && typeof module.default.validate === 'function') {
        this.register(module.default as CommunityValidator);
      } else {
        throw new Error(`Module at ${validatorPath} does not export a valid CommunityValidator as default.`);
      }
    } catch (error) {
      console.error(`Failed to load dynamic validator from ${validatorPath}:`, error);
      throw error;
    }
  }

  private registerBuiltIns(): void {
    this.register(new BannedCompetitorsValidator());
    this.register(new ToxicityKeywordsValidator());
    this.register(new UrlSafetyValidator());
    this.register(new CodeInjectionValidator());
  }
}

export class BannedCompetitorsValidator implements CommunityValidator {
  id = 'community.banned-competitors';
  description = 'Detects mentions of banned competitor names.';

  private competitors = ['competitor_a', 'competitor_b', 'evil_corp'];

  validate(input: string): ValidatorVerdict {
    const lowerInput = input.toLowerCase();
    const found = this.competitors.filter(c => lowerInput.includes(c));
    if (found.length > 0) {
      return {
        passed: false,
        score: 1.0,
        reason: `Found banned competitors: ${found.join(', ')}`
      };
    }
    return { passed: true, score: 0.0, reason: 'No competitors found.' };
  }
}

export class ToxicityKeywordsValidator implements CommunityValidator {
  id = 'community.toxicity-keywords';
  description = 'Detects toxic or offensive keywords.';

  private toxicWords = ['toxic_word', 'offensive_term', 'bad_word'];

  validate(input: string): ValidatorVerdict {
    const lowerInput = input.toLowerCase();
    const found = this.toxicWords.filter(c => lowerInput.includes(c));
    if (found.length > 0) {
      return {
        passed: false,
        score: Math.min(found.length * 0.5, 1.0),
        reason: `Found toxic keywords: ${found.join(', ')}`
      };
    }
    return { passed: true, score: 0.0, reason: 'No toxic keywords found.' };
  }
}

export class UrlSafetyValidator implements CommunityValidator {
  id = 'community.url-safety';
  description = 'Detects unsafe URLs.';

  private unsafeDomains = ['malware.com', 'phishing.net'];

  validate(input: string): ValidatorVerdict {
    const lowerInput = input.toLowerCase();
    const found = this.unsafeDomains.filter(c => lowerInput.includes(c));
    if (found.length > 0) {
      return {
        passed: false,
        score: 1.0,
        reason: `Found unsafe domains: ${found.join(', ')}`
      };
    }
    return { passed: true, score: 0.0, reason: 'No unsafe URLs found.' };
  }
}

export class CodeInjectionValidator implements CommunityValidator {
  id = 'community.code-injection';
  description = 'Detects potential code injection payloads.';

  private patterns = [/\beval\s*\(/i, /\bexec\s*\(/i, /\bsystem\s*\(/i, /<script\b/i];

  validate(input: string): ValidatorVerdict {
    for (const pattern of this.patterns) {
      if (pattern.test(input)) {
        return {
          passed: false,
          score: 1.0,
          reason: `Potential code injection detected by pattern ${pattern.toString()}`
        };
      }
    }
    return { passed: true, score: 0.0, reason: 'No code injection detected.' };
  }
}
