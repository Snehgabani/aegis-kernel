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

export const SANITIZER_HOMOGLYPH_DECODE_MAP: Record<string, string> = {
  // Cyrillic Lowercase
  '\u0430': 'a', '\u0431': 'b', '\u0432': 'b', '\u0433': 'r', '\u0434': 'd',
  '\u0435': 'e', '\u0451': 'e', '\u0454': 'e', '\u0436': 'z', '\u0437': 'z',
  '\u0438': 'u', '\u0456': 'i', '\u0457': 'i', '\u0458': 'j', '\u043A': 'k',
  '\u043B': 'l', '\u043C': 'm', '\u043D': 'n', '\u043E': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0442': 't', '\u0443': 'y', '\u0444': 'f', '\u0445': 'x',
  '\u0455': 's', '\u0491': 'g', '\u04bb': 'h', '\u04cf': 'l', '\u044c': 'b',
  '\u0501': 'd',

  // Cyrillic Uppercase
  '\u0410': 'A', '\u0411': 'B', '\u0412': 'B', '\u0413': 'R', '\u0414': 'D',
  '\u0415': 'E', '\u0401': 'E', '\u0404': 'E', '\u0416': 'Z', '\u0417': 'Z',
  '\u0418': 'U', '\u0406': 'I', '\u0407': 'I', '\u0408': 'J', '\u041A': 'K',
  '\u041B': 'L', '\u041C': 'M', '\u041D': 'H', '\u041E': 'O', '\u0420': 'P',
  '\u0421': 'C', '\u0422': 'T', '\u0423': 'Y', '\u0424': 'F', '\u0425': 'X',
  '\u0405': 'S', '\u0490': 'G', '\u04ba': 'H', '\u04c0': 'I', '\u042c': 'B',
  '\u0500': 'D',

  // Greek Lowercase
  '\u03B1': 'a', '\u03B2': 'b', '\u03B3': 'g', '\u03B4': 'd', '\u03B5': 'e',
  '\u03F5': 'e', '\u03B6': 'z', '\u03B7': 'h', '\u03B8': 'o', '\u03B9': 'i',
  '\u03BA': 'k', '\u03BB': 'l', '\u03BC': 'm', '\u03BD': 'n', '\u03BF': 'o',
  '\u03C0': 'p', '\u03C1': 'p', '\u03C2': 's', '\u03C3': 's', '\u03F2': 'c',
  '\u03C4': 't', '\u03C5': 'u', '\u03C7': 'x', '\u03C9': 'w',

  // Greek Uppercase
  '\u0391': 'A', '\u0392': 'B', '\u0393': 'G', '\u0394': 'D', '\u0395': 'E',
  '\u0396': 'Z', '\u0397': 'H', '\u0398': 'O', '\u0399': 'I', '\u039A': 'K',
  '\u039B': 'L', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O', '\u03A0': 'P',
  '\u03A1': 'P', '\u03A3': 'S', '\u03F9': 'C', '\u03A4': 'T', '\u03A5': 'Y',
  '\u03A7': 'X', '\u03A9': 'O',
};

export class AegisSanitizer {
  // Non-backtracking, linear O(n) PII and Secret patterns
  private static readonly CC_REGEX = /\b\d{4}(?:[ -]\d{4}){3}\b|\b\d{16}\b/g;
  private static readonly SSN_REGEX = /\b\d{3}-\d{2}-\d{4}\b/g;
  private static readonly INVISIBLE_UNICODE_REGEX =
    /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\uFFA0\uFFF9-\uFFFB]/g;
  private static readonly UNICODE_SPACES_REGEX = /[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g;

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

  public static normalizeUnicode(text: string): { normalized: string; wasModified: boolean } {
    const pre = text.replace(/\u03F2/g, 'c').replace(/\u03F9/g, 'C');
    const res = pre
      .normalize('NFKD')
      .replace(this.INVISIBLE_UNICODE_REGEX, '')
      .replace(this.UNICODE_SPACES_REGEX, ' ');

    let decoded = '';
    for (const ch of res) {
      decoded += SANITIZER_HOMOGLYPH_DECODE_MAP[ch] ?? ch;
    }

    return {
      normalized: decoded,
      wasModified: decoded !== text,
    };
  }

  private static deepCloneAndSanitize(value: any, mods: string[]): any {
    if (typeof value === 'string') {
      let result = value;

      // 0. Full Unicode normalization (NFKD, invisible/bidi stripping, homoglyph decoding, space normalization)
      const { normalized, wasModified } = this.normalizeUnicode(result);
      if (wasModified) {
        result = normalized;
        mods.push('Stripped hidden zero-width unicode evasion characters');
        mods.push('Normalized unicode compatibility characters (fullwidth/homoglyphs/bidi/invisible)');
      }

      // 1. Redact Credit Cards (O(n) linear non-backtracking regex)
      AegisSanitizer.CC_REGEX.lastIndex = 0;
      const afterCC = result.replace(AegisSanitizer.CC_REGEX, '[REDACTED_CREDIT_CARD]');
      if (afterCC !== result) {
        result = afterCC;
        mods.push('Masked plaintext Primary Account Number (PAN)');
      }

      // 2. Redact SSNs
      AegisSanitizer.SSN_REGEX.lastIndex = 0;
      const afterSSN = result.replace(AegisSanitizer.SSN_REGEX, '[REDACTED_SSN]');
      if (afterSSN !== result) {
        result = afterSSN;
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

