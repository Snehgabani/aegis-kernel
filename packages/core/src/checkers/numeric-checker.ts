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
    const val = this.extractNestedNumber(toolCall.params, params.field);

    // If the field is not present on this tool call, this numeric rule does not apply
    if (val === null || val === undefined) {
      return violations;
    }

    if (params.min !== undefined && val < params.min) {
      violations.push({
        ruleId,
        packId,
        severity: 'critical',
        message: `Numeric parameter '${params.field}' (${val}) is below minimum allowed value of ${params.min}.`,
        suggestedFix: `Increase value of '${params.field}' to at least ${params.min}.`,
        context: { field: params.field, actual: val, minimum: params.min },
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

    // Rate Limiting Check (Sliding Window) for matching field operations
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

  private extractNestedNumber(params: Record<string, unknown>, pathStr: string): number | null {
    if (!params || typeof params !== 'object') return null;
    const cleanPath = pathStr.replace(/^params\./, '');
    const parts = cleanPath.split('.');
    let current: any = params;

    let directFound = true;
    for (const part of parts) {
      if (current === null || current === undefined || typeof current !== 'object') {
        directFound = false;
        break;
      }
      current = current[part];
    }

    if (directFound && current !== null && current !== undefined) {
      const num = Number(current);
      if (!isNaN(num) && typeof current !== 'boolean') {
        return num;
      }
    }

    // Fallback: search recursively for target field name in nested objects
    const targetField = parts[parts.length - 1];
    return this.findNestedNumber(params, targetField);
  }

  private findNestedNumber(obj: unknown, fieldName: string): number | null {
    if (!obj || typeof obj !== 'object') return null;
    const record = obj as Record<string, unknown>;

    if (fieldName in record && record[fieldName] !== null && record[fieldName] !== undefined) {
      const num = Number(record[fieldName]);
      if (!isNaN(num) && typeof record[fieldName] !== 'boolean') {
        return num;
      }
    }

    for (const val of Object.values(record)) {
      if (val && typeof val === 'object') {
        const found = this.findNestedNumber(val, fieldName);
        if (found !== null) return found;
      }
    }

    return null;
  }
}
