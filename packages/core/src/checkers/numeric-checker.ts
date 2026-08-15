import type { AegisViolation, NumericConditionParams, ToolCall } from '../types.js';

export class NumericChecker {
  private rateLimitWindows: Map<string, number[]>;

  constructor() {
    this.rateLimitWindows = new Map();
  }

  public evaluate(
    ruleId: string,
    packId: string,
    params: NumericConditionParams,
    toolCall: ToolCall
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
        severity: 'critical',
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
      if (lowerField.includes('amount') || lowerField.includes('price') || lowerField.includes('cost') ||
          lowerField.includes('payment') || lowerField.includes('payout') || lowerField.includes('transfer')) {
        effectiveMin = 0;
      }
    }

    if (effectiveMin !== undefined && val < effectiveMin) {
      violations.push({
        ruleId,
        packId,
        severity: 'critical',
        message: `Numeric parameter '${params.field}' (${val}) is below minimum allowed value of ${effectiveMin}.`,
        suggestedFix: `Increase value of '${params.field}' to at least ${effectiveMin}.`,
        context: { field: params.field, actual: val, minimum: effectiveMin },
      });
    }

    if (params.max !== undefined && val > params.max) {
      violations.push({
        ruleId,
        packId,
        severity: 'critical',
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
          severity: 'critical',
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

      // Strip currency codes, symbols, and commas
      const normalized = trimmed
        .replace(/[$€£¥₹]/g, '')
        .replace(/\b(USD|EUR|GBP|CAD|AUD|INR)\b/gi, '')
        .replace(/,/g, '')
        .trim();

      const parsed = Number(normalized);
      if (Number.isFinite(parsed)) {
        return parsed;
      }
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
    return recursiveResult;
  }

  private findNestedNumber(
    obj: unknown,
    fieldName: string,
    visited: Set<unknown> = new Set()
  ): { status: 'valid'; value: number } | { status: 'invalid'; rawValue: unknown } | { status: 'absent' } {
    if (!obj || typeof obj !== 'object' || visited.has(obj)) return { status: 'absent' };
    visited.add(obj);
    const record = obj as Record<string, unknown>;

    if (fieldName in record) {
      const raw = record[fieldName];
      const parsed = this.parseNumericValue(raw);
      if (parsed !== null) {
        return { status: 'valid', value: parsed };
      }
      return { status: 'invalid', rawValue: raw };
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
