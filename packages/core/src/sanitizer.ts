/**
 * Aegis Invariant Kernel — In-Flight Parameter Sanitizer & Rewriter
 *
 * Instead of only hard-blocking tool calls, the Sanitizer mutates unsafe
 * tool arguments into strictly safe, compliant representations in-flight.
 */

import type { ToolCall } from './types.js';

export interface SanitizationResult {
  original: ToolCall;
  sanitized: ToolCall;
  wasModified: boolean;
  modifications: string[];
}

export class AegisSanitizer {
  // Non-backtracking, linear O(n) PII and Secret patterns
  private static readonly CC_REGEX = /\b\d{4}(?:[ -]\d{4}){3}\b|\b\d{16}\b/g;
  private static readonly SSN_REGEX = /\b\d{3}-\d{2}-\d{4}\b/g;
  private static readonly ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u202A-\u202E]/g;

  /**
   * Sanitizes a tool call by mutating unsafe parameters in-place safely.
   */
  public static sanitize(toolCall: ToolCall): SanitizationResult {
    const modifications: string[] = [];
    const sanitizedParams = this.deepCloneAndSanitize(toolCall.params, modifications);

    // SQL Specific Auto-Limit Injection without regex backtracking
    if (typeof sanitizedParams === 'object' && sanitizedParams !== null) {
      const p = sanitizedParams as Record<string, any>;
      if (p.query && typeof p.query === 'string') {
        const trimmed = p.query.trim();
        if (/^SELECT\b/i.test(trimmed) && !/\bLIMIT\s+\d+/i.test(trimmed)) {
          const stripped = trimmed.endsWith(';') ? trimmed.slice(0, -1).trimEnd() : trimmed;
          p.query = `${stripped} LIMIT 100;`;
          modifications.push('Injected mandatory LIMIT 100 into unbound SELECT query');
        }
      }
      if (p.sql && typeof p.sql === 'string') {
        const trimmed = p.sql.trim();
        if (/^SELECT\b/i.test(trimmed) && !/\bLIMIT\s+\d+/i.test(trimmed)) {
          const stripped = trimmed.endsWith(';') ? trimmed.slice(0, -1).trimEnd() : trimmed;
          p.sql = `${stripped} LIMIT 100;`;
          modifications.push('Injected mandatory LIMIT 100 into unbound SELECT query');
        }
      }
    }

    return {
      original: toolCall,
      sanitized: {
        tool: toolCall.tool,
        params: sanitizedParams,
      },
      wasModified: modifications.length > 0,
      modifications,
    };
  }

  private static deepCloneAndSanitize(value: any, mods: string[]): any {
    if (typeof value === 'string') {
      let result = value;

      // 1. Strip zero-width unicode
      if (this.ZERO_WIDTH_REGEX.test(result)) {
        result = result.replace(this.ZERO_WIDTH_REGEX, '');
        mods.push('Stripped hidden zero-width unicode evasion characters');
      }

      // 2. Redact Credit Cards (O(n) linear non-backtracking regex)
      if (this.CC_REGEX.test(result)) {
        result = result.replace(this.CC_REGEX, '[REDACTED_CREDIT_CARD]');
        mods.push('Masked plaintext Primary Account Number (PAN)');
      }

      // 3. Redact SSNs
      if (this.SSN_REGEX.test(result)) {
        result = result.replace(this.SSN_REGEX, '[REDACTED_SSN]');
        mods.push('Masked plaintext Social Security Number (SSN)');
      }

      return result;
    }

    if (Array.isArray(value)) {
      return value.map((item) => this.deepCloneAndSanitize(item, mods));
    }

    if (typeof value === 'object' && value !== null) {
      const cloned: Record<string, any> = {};
      for (const [k, v] of Object.entries(value)) {
        cloned[k] = this.deepCloneAndSanitize(v, mods);
      }
      return cloned;
    }

    return value;
  }
}
