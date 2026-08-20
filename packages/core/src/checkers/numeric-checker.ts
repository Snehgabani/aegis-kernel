import type { AegisViolation, NumericConditionParams, ToolCall } from '../types.js';
import { HOMOGLYPH_DECODE_MAP } from './sql-checker.js';

export class NumericChecker {
  private rateLimitWindows: Map<string, number[]>;

  constructor() {
    this.rateLimitWindows = new Map();
  }

  public resetRateLimits(): void {
    this.rateLimitWindows.clear();
  }

  public evaluate(
    ruleId: string,
    packId: string,
    params: NumericConditionParams,
    toolCall: ToolCall,
    severity: import("../types.js").AegisSeverity = "critical"
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];
    const extraction = this.extractNestedNumber(toolCall.params, params.field);

    // If the field is not present at all on this tool call, this rule does not apply
    if (extraction.status === 'absent') {
      return violations;
    }

    // If the field is present but has an invalid/malformed non-numeric type (e.g. "NaN", {}, [])
    if (extraction.status === 'invalid') {
      violations.push({
        ruleId,
        packId,
        severity,
        message: `Numeric parameter '${params.field}' contains invalid or unparseable non-numeric value: ${JSON.stringify(extraction.rawValue)}.`,
        suggestedFix: `Ensure '${params.field}' is a valid finite numeric value or formatted currency string.`,
        context: { field: params.field, rawValue: extraction.rawValue },
      });
      return violations;
    }

    const val = extraction.value;

    let effectiveMin = params.min;
    if (effectiveMin === undefined) {
      const lowerField = params.field.toLowerCase();
      const financialNames = [
        'amount', 'price', 'cost', 'payment', 'payout', 'transfer',
        'balance', 'credit', 'debit', 'total', 'value', 'sum', 'fee', 'charge', 'limit'
      ];
      if (financialNames.some(name => lowerField.includes(name))) {
        effectiveMin = 0;
      }
    }

    if (effectiveMin !== undefined && val < effectiveMin) {
      violations.push({
        ruleId,
        packId,
        severity,
        message: `Numeric parameter '${params.field}' (${val}) is below minimum allowed value of ${effectiveMin}.`,
        suggestedFix: `Increase value of '${params.field}' to at least ${effectiveMin}.`,
        context: { field: params.field, actual: val, minimum: effectiveMin },
      });
    }

    if (params.max !== undefined && val > params.max) {
      violations.push({
        ruleId,
        packId,
        severity,
        message: `Numeric parameter '${params.field}' (${val}) exceeds maximum allowed limit of ${params.max}.`,
        suggestedFix: `Reduce value of '${params.field}' to ${params.max} or less.`,
        context: { field: params.field, actual: val, maximum: params.max },
      });
    }

    // Rate Limiting Check (Sliding Window)
    if (params.rate_limit) {
      const now = Date.now();
      const windowMs = 60 * 1000;
      const key = `${packId}:${ruleId}:${toolCall.tool}`;

      let timestamps = this.rateLimitWindows.get(key) || [];
      timestamps = timestamps.filter((t) => now - t < windowMs);
      timestamps.push(now);
      this.rateLimitWindows.set(key, timestamps);

      if (timestamps.length > params.rate_limit.max_per_minute) {
        violations.push({
          ruleId,
          packId,
          severity,
          message: `Rate limit ceiling reached: Tool '${toolCall.tool}' invoked ${timestamps.length} times in past minute (max: ${params.rate_limit.max_per_minute}).`,
          suggestedFix: `Throttle tool invocation frequency or batch operations.`,
          context: {
            currentCount: timestamps.length,
            maxPerMinute: params.rate_limit.max_per_minute,
          },
        });
      }
    }

    return violations;
  }

  private parseNumericValue(val: unknown): number | null {
    if (val === null || val === undefined || typeof val === 'boolean') {
      return null;
    }

    // 1. Direct finite number
    if (typeof val === 'number') {
      return Number.isFinite(val) ? val : null;
    }

    // 2. Safe BigInt handling
    if (typeof val === 'bigint') {
      return Number(val);
    }

    // 3. Formatted currency / numeric string parsing ($5,000.00, €10,000, 1,000.50 USD)
    if (typeof val === 'string') {
      const trimmed = val.trim();
      if (!trimmed || trimmed.toLowerCase() === 'nan' || trimmed.toLowerCase() === 'infinity') {
        return null;
      }

      const parsed = this.tryParseNumberString(trimmed);
      if (parsed !== null) {
        return parsed;
      }

      // 4. (2026-08-21, M4 property finding) Encoded-numeric evasion: an
      // amount delivered as "BASE64_DATA: OTk5...", zero-width-spaced digits,
      // or percent/hex-encoded text previously parsed to null and skipped the
      // bound check entirely. Decode (bounded) before parsing.
      return this.decodeEncodedNumeric(trimmed);
    }

    return null;
  }

  private tryParseNumberString(raw: string): number | null {
    // Strip currency codes, symbols, and commas
    const normalized = raw
      .replace(/[$€£¥₹]/g, '')
      .replace(/\b(USD|EUR|GBP|CAD|AUD|INR)\b/gi, '')
      .replace(/,/g, '')
      .replace(/BASE64_DATA:/gi, '')
      .trim();

    const parsed = Number(normalized);
    return Number.isFinite(parsed) ? parsed : null;
  }

  /**
   * Bounded decode cascade for numerics hidden behind encoding layers:
   * strip invisibles/separators → fold confusables → base64 / percent / hex.
   * Depth ≤ 2; candidates must parse as finite numbers to be accepted.
   */
  private decodeEncodedNumeric(raw: string): number | null {
    if (raw.length > 512) return null;
    const stripped = raw.replace(
      /[\u00AD\u061C\u180E\u2000-\u200F\u202A-\u202E\u202F\u205F\u2060-\u2064\u2066-\u206F\u3000\uFEFF]/g,
      ''
    );
    const folded = Array.from(stripped)
      .map((ch) => HOMOGLYPH_DECODE_MAP[ch] ?? ch)
      .join('');

    const candidates: string[] = [folded];
    const b64 = folded.match(/([A-Za-z0-9+/=_-]{8,})/);
    if (b64) {
      try {
        const decoded = Buffer.from(b64[1].replace(/=+$/, ''), 'base64').toString('utf8');
        if (decoded.replace(/[^\x20-\x7E]/g, '').length / Math.max(decoded.length, 1) > 0.8) {
          candidates.push(decoded);
          // layer 2 (double-wrapped)
          const inner = decoded.match(/([A-Za-z0-9+/=_-]{8,})/);
          if (inner) {
            try {
              candidates.push(Buffer.from(inner[1].replace(/=+$/, ''), 'base64').toString('utf8'));
            } catch {
              /* ignore */
            }
          }
        }
      } catch {
        /* ignore */
      }
    }
    const pct = folded.match(/(?:%[0-9A-Fa-f]{2}){2,}/);
    if (pct) {
      try {
        candidates.push(decodeURIComponent(pct[0]));
      } catch {
        /* ignore */
      }
    }
    const hex = folded.match(/(?:\\x[0-9A-Fa-f]{2}){2,}/);
    if (hex) {
      candidates.push(hex[0].replace(/\\x([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))));
    }

    for (const candidate of candidates) {
      const n = this.tryParseNumberString(candidate);
      if (n !== null) return n;
    }
    return null;
  }

  private extractNestedNumber(
    params: Record<string, unknown>,
    pathStr: string
  ): { status: 'valid'; value: number } | { status: 'invalid'; rawValue: unknown } | { status: 'absent' } {
    if (!params || typeof params !== 'object') return { status: 'absent' };
    const cleanPath = pathStr.replace(/^params\./, '');
    const parts = cleanPath.split('.');
    let current: any = params;

    let directFound = true;
    for (const part of parts) {
      if (current === null || current === undefined || typeof current !== 'object' || !(part in current)) {
        directFound = false;
        break;
      }
      current = current[part];
    }

    if (directFound) {
      const parsed = this.parseNumericValue(current);
      if (parsed !== null) {
        return { status: 'valid', value: parsed };
      }
      return { status: 'invalid', rawValue: current };
    }

    // Fallback: search recursively for target field name in nested objects
    const targetField = parts[parts.length - 1];
    const recursiveResult = this.findNestedNumber(params, targetField);
    if (recursiveResult.status !== 'absent') {
      return recursiveResult;
    }

    // Semantic alias search for financial fields (e.g. amount -> total, value, sum, price, payout)
    const lowerTarget = targetField.toLowerCase();
    const financialAliases = ['amount', 'total', 'value', 'sum', 'price', 'cost', 'payout', 'payment', 'transfer', 'fee', 'charge', 'subtotal', 'debit', 'credit', 'balance', 'limit'];
    if (financialAliases.includes(lowerTarget)) {
      for (const alias of financialAliases) {
        if (alias === lowerTarget) continue;
        const aliasResult = this.findNestedNumber(params, alias);
        if (aliasResult.status !== 'absent') {
          return aliasResult;
        }
      }
    }

    return { status: 'absent' };
  }

  private findNestedNumber(
    obj: unknown,
    fieldName: string,
    visited: Set<unknown> = new Set()
  ): { status: 'valid'; value: number } | { status: 'invalid'; rawValue: unknown } | { status: 'absent' } {
    if (!obj || typeof obj !== 'object' || visited.has(obj)) return { status: 'absent' };
    visited.add(obj);
    const record = obj as Record<string, unknown>;

    // Case-insensitive property lookup
    const lowerTarget = fieldName.toLowerCase();
    for (const [key, raw] of Object.entries(record)) {
      if (key.toLowerCase() === lowerTarget) {
        const parsed = this.parseNumericValue(raw);
        if (parsed !== null) {
          return { status: 'valid', value: parsed };
        }
        return { status: 'invalid', rawValue: raw };
      }
    }

    for (const val of Object.values(record)) {
      if (val && typeof val === 'object') {
        const found = this.findNestedNumber(val, fieldName, visited);
        if (found.status !== 'absent') return found;
      }
    }

    return { status: 'absent' };
  }
}
