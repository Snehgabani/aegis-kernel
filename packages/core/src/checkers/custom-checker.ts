import type { AegisViolation, CustomConditionParams, ToolCall } from '../types.js';

/**
 * Zero-Eval Declarative Expression Evaluator
 *
 * Implements a completely safe, deterministic AST-free recursive-descent evaluator
 * for parameter constraints and arithmetic. Zero use of eval(), new Function(), or node:vm.
 * Completely immune to prototype pollution, sandbox escapes, and code injection.
 */
export class CustomChecker {
  public evaluate(
    ruleId: string,
    packId: string,
    params: CustomConditionParams,
    toolCall: ToolCall
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];

    try {
      const shouldBlock = this.evaluateExpression(params.predicate, toolCall.params);

      if (shouldBlock) {
        violations.push({
          ruleId,
          packId,
          severity: 'critical',
          message: `Declarative policy predicate triggered for tool '${toolCall.tool}'.`,
          suggestedFix: `Adjust tool call arguments to satisfy policy condition: ${params.predicate}`,
          context: { predicate: params.predicate },
        });
      }
    } catch (err: any) {
      violations.push({
        ruleId,
        packId,
        severity: 'warning',
        message: `Policy expression evaluation error: ${err.message}`,
        context: { predicate: params.predicate, error: err.message },
      });
    }

    return violations;
  }

  /**
   * Safe evaluation of a boolean expression against parameters
   */
  public evaluateExpression(expr: string, contextParams: Record<string, unknown>): boolean {
    const trimmed = expr.trim();
    if (!trimmed) return false;

    // Handle logical OR (||)
    const orParts = this.splitByTopLevelOperator(trimmed, '||');
    if (orParts.length > 1) {
      return orParts.some((p) => this.evaluateExpression(p, contextParams));
    }

    // Handle logical AND (&&)
    const andParts = this.splitByTopLevelOperator(trimmed, '&&');
    if (andParts.length > 1) {
      return andParts.every((p) => this.evaluateExpression(p, contextParams));
    }

    // Handle negation (!)
    if (trimmed.startsWith('!') && !trimmed.startsWith('!=')) {
      return !this.evaluateExpression(trimmed.slice(1).trim(), contextParams);
    }

    // Handle comparison operators: ===, !==, ==, !=, <=, >=, <, >, in, contains
    const operators = ['===', '!==', '==', '!=', '<=', '>=', '<', '>', ' in ', ' contains '];
    for (const op of operators) {
      const parts = this.splitByTopLevelOperator(trimmed, op);
      if (parts.length === 2) {
        const leftVal = this.resolveValue(parts[0].trim(), contextParams);
        const rightVal = this.resolveValue(parts[1].trim(), contextParams);
        const cleanOp = op.trim();

        switch (cleanOp) {
          case '===':
          case '==':
            return leftVal == rightVal; // eslint-disable-line eqeqeq
          case '!==':
          case '!=':
            return leftVal != rightVal; // eslint-disable-line eqeqeq
          case '<':
            return Number(leftVal) < Number(rightVal);
          case '<=':
            return Number(leftVal) <= Number(rightVal);
          case '>':
            return Number(leftVal) > Number(rightVal);
          case '>=':
            return Number(leftVal) >= Number(rightVal);
          case 'in':
            if (Array.isArray(rightVal)) {
              return rightVal.includes(leftVal);
            }
            if (typeof rightVal === 'string') {
              return rightVal.includes(String(leftVal));
            }
            return false;
          case 'contains':
            if (Array.isArray(leftVal)) {
              return leftVal.includes(rightVal);
            }
            if (typeof leftVal === 'string') {
              return leftVal.includes(String(rightVal));
            }
            return false;
        }
      }
    }

    // Single value boolean coercion
    const singleVal = this.resolveValue(trimmed, contextParams);
    return Boolean(singleVal);
  }

  private splitByTopLevelOperator(expr: string, op: string): string[] {
    const results: string[] = [];
    let depth = 0;
    let inQuote: string | null = null;
    let lastIndex = 0;
    const opLen = op.length;

    for (let i = 0; i < expr.length; i++) {
      const char = expr[i];

      if (inQuote) {
        if (char === inQuote && expr[i - 1] !== '\\') {
          inQuote = null;
        }
        continue;
      }

      if (char === "'" || char === '"' || char === '`') {
        inQuote = char;
        continue;
      }

      if (char === '(' || char === '[') depth++;
      else if (char === ')' || char === ']') depth--;

      if (depth === 0 && expr.slice(i, i + opLen) === op) {
        results.push(expr.slice(lastIndex, i));
        lastIndex = i + opLen;
        i += opLen - 1;
      }
    }

    if (lastIndex > 0) {
      results.push(expr.slice(lastIndex));
      return results;
    }

    return [expr];
  }

  public resolveValue(token: string, contextParams: Record<string, unknown>): unknown {
    const trimmed = token.trim();

    // Check for arithmetic addition/subtraction: a + b, a - b
    const addParts = this.splitByTopLevelOperator(trimmed, '+');
    if (addParts.length > 1) {
      return addParts.reduce((acc, part) => Number(acc) + Number(this.resolveValue(part.trim(), contextParams)), 0);
    }

    const subParts = this.splitByTopLevelOperator(trimmed, '-');
    if (subParts.length > 1 && !trimmed.startsWith('-')) {
      const first = Number(this.resolveValue(subParts[0].trim(), contextParams));
      const rest = subParts.slice(1).map((p) => Number(this.resolveValue(p.trim(), contextParams)));
      return rest.reduce((acc, val) => acc - val, first);
    }

    // String literal
    if (
      (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
      (trimmed.startsWith('"') && trimmed.endsWith('"'))
    ) {
      return trimmed.slice(1, -1);
    }

    // Number literal
    if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
      return Number(trimmed);
    }

    // Boolean literal
    if (trimmed === 'true') return true;
    if (trimmed === 'false') return false;
    if (trimmed === 'null') return null;
    if (trimmed === 'undefined') return undefined;

    // Array literal: ['a', 'b', 123]
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      const inside = trimmed.slice(1, -1).trim();
      if (!inside) return [];
      const items = this.splitByTopLevelOperator(inside, ',');
      return items.map((item) => this.resolveValue(item.trim(), contextParams));
    }

    // Dot-notation Path lookup on params / state / root
    const cleanPath = trimmed.replace(/^params\./, '');
    const parts = cleanPath.split('.');
    let current: any = contextParams;

    for (const part of parts) {
      if (current === null || current === undefined || typeof current !== 'object') {
        return undefined;
      }
      current = current[part];
    }

    if (current !== undefined) return current;

    // Try direct key on contextParams
    return (contextParams as any)[trimmed];
  }
}
