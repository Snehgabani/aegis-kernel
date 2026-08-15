import { randomBytes } from 'node:crypto';
import { DEFAULT_PII_PATTERNS } from '../checkers/pii-checker.js';

export interface TokenizeResult {
  sanitized: string;
  tokensCreated: number;
  tokenTypes: Record<string, number>;
}

export interface DetokenizeResult {
  restored: string;
  tokensRestored: number;
}

export interface PiiTokenVaultConfig {
  patterns?: Record<string, RegExp>;
  tokenPrefix?: string;
  hashLength?: number;
}

export class PiiTokenVault {
  private patterns: Record<string, RegExp>;
  private vault: Map<string, string>; // Maps token to original value
  private valueToTokenMap: Map<string, string>; // Maps original value to token for reuse
  private tokenPrefix: string;
  private hashLength: number;

  constructor(config?: PiiTokenVaultConfig) {
    this.patterns = config?.patterns ?? DEFAULT_PII_PATTERNS;
    this.vault = new Map();
    this.valueToTokenMap = new Map();
    this.tokenPrefix = config?.tokenPrefix ?? '';
    this.hashLength = config?.hashLength ?? 8;
  }

  public tokenize(text: string): TokenizeResult {
    if (!text || typeof text !== 'string') {
      return { sanitized: text, tokensCreated: 0, tokenTypes: {} };
    }

    let sanitized = text;
    let tokensCreated = 0;
    const tokenTypes: Record<string, number> = {};

    for (const [type, pattern] of Object.entries(this.patterns)) {
      let regexFlags = 'g';
      if (pattern.ignoreCase) regexFlags += 'i';
      if (pattern.multiline) regexFlags += 'm';
      
      const globalPattern = new RegExp(pattern.source, regexFlags);
      
      sanitized = sanitized.replace(globalPattern, (match) => {
        const existingToken = this.valueToTokenMap.get(match);
        if (existingToken) {
          return existingToken;
        }

        const randomHex = randomBytes(Math.ceil(this.hashLength / 2)).toString('hex').slice(0, this.hashLength);
        const prefix = this.tokenPrefix ? `${this.tokenPrefix}_` : `${type}_`;
        const token = `<${prefix}${randomHex}>`;

        this.vault.set(token, match);
        this.valueToTokenMap.set(match, token);
        
        tokensCreated++;
        tokenTypes[type] = (tokenTypes[type] || 0) + 1;
        
        return token;
      });
    }

    return {
      sanitized,
      tokensCreated,
      tokenTypes
    };
  }

  public detokenize(text: string): DetokenizeResult {
    if (!text || typeof text !== 'string') {
      return { restored: text, tokensRestored: 0 };
    }

    let restored = text;
    let tokensRestored = 0;
    const tokenRegex = /<[A-Za-z0-9_]+>/g;
    
    restored = restored.replace(tokenRegex, (match) => {
      const originalValue = this.vault.get(match);
      if (originalValue !== undefined) {
        tokensRestored++;
        return originalValue;
      }
      return match;
    });

    return {
      restored,
      tokensRestored
    };
  }

  public clear(): void {
    this.vault.clear();
    this.valueToTokenMap.clear();
  }

  public getVaultSize(): number {
    return this.vault.size;
  }
}
