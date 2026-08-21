import type { AegisViolation, EvaluationScratch, NumericConditionParams, ToolCall } from '../types.js';
import { HOMOGLYPH_DECODE_MAP } from './sql-checker.js';

// Module-level constants — no per-call array allocations on the hot path.
const FINANCIAL_NAME_HINTS = [
  'amount', 'price', 'cost', 'payment', 'payout', 'transfer',
  'balance', 'credit', 'debit', 'total', 'value', 'sum', 'fee', 'charge', 'limit',
] as const;

const FINANCIAL_ALIASES = [
  'amount', 'total', 'value', 'sum', 'price', 'cost', 'payout', 'payment', 'transfer',
  'fee', 'charge', 'subtotal', 'debit', 'credit', 'balance', 'limit',
] as const;

const INVISIBLE_EVASION_RE =
  /[\u00AD\u061C\u180E\u2000-\u200F\u202A-\u202E\u202F\u205F\u2060-\u2064\u2066-\u206F\u3000\uFEFF]/g;

const CURRENCY_SYMBOL_RE = /[$€£¥₹]/g;
const CURRENCY_CODE_RE = /\b(USD|EUR|GBP|CAD|AUD|INR)\b/gi;
const BASE64_DATA_RE = /BASE64_DATA:/gi;

type NumericExtractionResult =
  | { status: 'valid'; value: number }
  | { status: 'invalid'; rawValue: unknown }
  | { status: 'absent' };

const ABSENT: NumericExtractionResult = { status: 'absent' };

export class NumericChecker {
  private rateLimitWindows: Map<string, number[]>;

  /**
   * Pure-function memo for string→number parsing. KEYED BY IMMUTABLE STRINGS
   * only, so it is safe across calls (a string cannot be mutated under us).
   * Bounded to prevent unbounded growth on adversarial input variety.
   */
  private parseMemo: Map<string, number | null>;

  constructor() {
    this.rateLimitWindows = new Map();
    this.parseMemo = new Map();
  }

  public resetRateLimits(): void {
    this.rateLimitWindows.clear();
  }

  public evaluate(
    ruleId: string,
    packId: string,
    params: NumericConditionParams,
    toolCall: ToolCall,
    severity: import("../types.js").AegisSeverity = "critical",
    scratch?: EvaluationScratch
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];
    const extraction = this.extractNestedNumber(toolCall.params, params.field, scratch);

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
      if (FINANCIAL_NAME_HINTS.some((name) => lowerField.includes(name))) {
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
      const max = params.rate_limit.max_per_minute;
      const key = `${packId}:${ruleId}:${toolCall.tool}`;

      let timestamps = this.rateLimitWindows.get(key);
      if (!timestamps) {
        timestamps = [];
        this.rateLimitWindows.set(key, timestamps);
      }
      // Bounded sliding window: prune expired entries, then cap retained
      // history at max_per_minute. The historical implementation kept EVERY
      // timestamp within the window, making each evaluate() O(calls) — a
      // 20k-call benchmark meant a ~20k-element filter + realloc per call.
      // With the cap, per-call work is O(max_per_minute) regardless of volume.
      let firstLive = 0;
      while (firstLive < timestamps.length && now - timestamps[firstLive]! >= windowMs) {
        firstLive++;
      }
      if (firstLive > 0) timestamps.splice(0, firstLive);
      // Already at capacity before this call ⇒ the call exceeds the ceiling.
      const exceeded = timestamps.length >= max;
      timestamps.push(now);
      if (timestamps.length > max) {
        timestamps.splice(0, timestamps.length - max);
      }

      if (exceeded) {
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

    // 3+4. Formatted currency / encoded strings — pure function of the string,
    // memoized (bounded) because several rules re-parse the same value.
    if (typeof val === 'string') {
      const cached = this.parseMemo.get(val);
      if (cached !== undefined) return cached;
      const parsed = this.parseNumericString(val);
      if (this.parseMemo.size >= 2048) {
        const first = this.parseMemo.keys().next().value;
        if (first !== undefined) this.parseMemo.delete(first);
      }
      this.parseMemo.set(val, parsed);
      return parsed;
    }

    return null;
  }

  private parseNumericString(trimmed: string): number | null {
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

  private tryParseNumberString(raw: string): number | null {
    // Strip currency codes, symbols, and commas
    const normalized = raw
      .replace(CURRENCY_SYMBOL_RE, '')
      .replace(CURRENCY_CODE_RE, '')
      .replace(/,/g, '')
      .replace(BASE64_DATA_RE, '')
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
    const stripped = raw.replace(INVISIBLE_EVASION_RE, '');
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

  /**
   * Single-pass field walk shared across all numeric rules of one evaluate().
   *
   * Builds (once per params object, per evaluate) a map of lowercased field
   * name → first-seen raw value. Subsequent rules probing the same or alias
   * fields hit the memo instead of re-walking the tree (the historical
   * implementation performed up to 17 separate DFS walks per numeric rule).
   */
  private collectFieldMap(
    params: Record<string, unknown>,
    scratch?: EvaluationScratch
  ): Map<string, unknown> {
    if (scratch) {
      const cached = scratch.numericFields.get(params);
      if (cached) return cached;
    }
    const map = new Map<string, unknown>();
    const visited = new Set<object>();
    const walk = (node: unknown): void => {
      if (!node || typeof node !== 'object' || visited.has(node)) return;
      visited.add(node);
      const record = node as Record<string, unknown>;
      // Entries-first ordering: record every key at this level BEFORE
      // recursing into children (matches historical findNestedNumber order).
      for (const key of Object.keys(record)) {
        const lower = key.toLowerCase();
        if (!map.has(lower)) map.set(lower, record[key]);
      }
      for (const key of Object.keys(record)) {
        const val = record[key];
        if (val && typeof val === 'object') walk(val);
      }
    };
    walk(params);
    if (scratch) scratch.numericFields.set(params, map);
    return map;
  }

  private extractNestedNumber(
    params: Record<string, unknown>,
    pathStr: string,
    scratch?: EvaluationScratch
  ): NumericExtractionResult {
    if (!params || typeof params !== 'object') return ABSENT;
    const cleanPath = pathStr.replace(/^params\./, '');
    const parts = cleanPath.split('.');

    // 1. Direct dotted path (params.amount, params.a.b)
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

    // 2. Recursive case-insensitive field search — one shared walk per call.
    const fieldMap = this.collectFieldMap(params, scratch);
    const targetField = parts[parts.length - 1].toLowerCase();

    if (fieldMap.has(targetField)) {
      const raw = fieldMap.get(targetField);
      const parsed = this.parseNumericValue(raw);
      if (parsed !== null) {
        return { status: 'valid', value: parsed };
      }
      return { status: 'invalid', rawValue: raw };
    }

    // 3. Semantic alias search for financial fields (amount -> total, value, sum, price, payout)
    if ((FINANCIAL_ALIASES as readonly string[]).includes(targetField)) {
      for (const alias of FINANCIAL_ALIASES) {
        if (alias === targetField) continue;
        if (fieldMap.has(alias)) {
          const raw = fieldMap.get(alias);
          const parsed = this.parseNumericValue(raw);
          if (parsed !== null) {
            return { status: 'valid', value: parsed };
          }
          return { status: 'invalid', rawValue: raw };
        }
      }
    }

    return ABSENT;
  }
}
