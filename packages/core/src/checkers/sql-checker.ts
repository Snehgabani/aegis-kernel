import NodeSqlParser from 'node-sql-parser';
import type { AegisViolation, SqlAstConditionParams, ToolCall } from '../types.js';

// Clean ESM/CJS interop for node-sql-parser
const ParserClass: any =
  (NodeSqlParser as any).Parser ??
  (NodeSqlParser as any).default?.Parser ??
  NodeSqlParser;

export class SqlChecker {
  private parser: any;

  constructor() {
    this.parser = new ParserClass();
  }

  public evaluate(
    ruleId: string,
    packId: string,
    params: SqlAstConditionParams,
    toolCall: ToolCall
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];
    const sql = this.extractSqlString(toolCall, params.database_field);

    if (!sql || typeof sql !== 'string' || !sql.trim()) {
      return violations;
    }

    try {
      // Primary: Full AST Parsing
      const ast = this.parser.astify(sql);
      const astList = Array.isArray(ast) ? ast : [ast];

      for (const statement of astList) {
        if (!statement || typeof statement !== 'object') continue;
        const stmtType = (statement.type ?? '').toUpperCase();

        // 1. Block prohibited statement types
        if (params.block_statements && params.block_statements.includes(stmtType as any)) {
          violations.push({
            ruleId,
            packId,
            severity: 'critical',
            message: `Statement type '${stmtType}' is prohibited by security policy.`,
            suggestedFix: `Avoid using '${stmtType}'. Use read-only queries or specific targeted updates instead.`,
            context: { statementType: stmtType, sql: sql.slice(0, 120) },
          });
        }

        // 2. Detect destructive ALTER TABLE DROP operations
        if (stmtType === 'ALTER') {
          const sqlUpper = sql.toUpperCase();
          if (
            sqlUpper.includes('DROP COLUMN') ||
            sqlUpper.includes('DROP CONSTRAINT') ||
            sqlUpper.includes('DROP')
          ) {
            violations.push({
              ruleId,
              packId,
              severity: 'critical',
              message: `Destructive schema modification 'ALTER TABLE ... DROP' detected.`,
              suggestedFix: `Destructive schema alterations are prohibited in production agent workflows.`,
              context: { statementType: 'ALTER_DROP', sql: sql.slice(0, 120) },
            });
          }
        }

        // 3. Prohibit DELETE without WHERE clause OR with tautological WHERE clause (e.g. WHERE 1=1)
        if (stmtType === 'DELETE') {
          if (params.require === 'WHERE_CLAUSE') {
            const hasWhere = Boolean((statement as any).where);
            const isTautology = this.isTautologyWhere((statement as any).where, sql);

            if (!hasWhere || isTautology) {
              violations.push({
                ruleId,
                packId,
                severity: 'critical',
                message: isTautology
                  ? `Mass DELETE statement detected with tautological WHERE clause (e.g. 1=1).`
                  : `Mass DELETE statement detected without WHERE clause.`,
                suggestedFix: `Specify target rows with specific predicate conditions (e.g. 'WHERE id = :id').`,
                context: { statementType: 'DELETE', tautology: isTautology, missing: !hasWhere },
              });
            }
          }
        }

        // 4. Prohibit UPDATE without WHERE clause OR with tautological WHERE clause
        if (stmtType === 'UPDATE') {
          if (params.require === 'WHERE_CLAUSE') {
            const hasWhere = Boolean((statement as any).where);
            const isTautology = this.isTautologyWhere((statement as any).where, sql);

            if (!hasWhere || isTautology) {
              violations.push({
                ruleId,
                packId,
                severity: 'critical',
                message: isTautology
                  ? `Mass UPDATE statement detected with tautological WHERE clause (e.g. 1=1).`
                  : `Mass UPDATE statement detected without WHERE clause.`,
                suggestedFix: `Specify target rows in a targeted WHERE clause (e.g. 'WHERE id = :id').`,
                context: { statementType: 'UPDATE', tautology: isTautology, missing: !hasWhere },
              });
            }
          }
        }

        // 5. Check Limit bounds
        if (params.max_limit && (statement as any).limit) {
          const limitVal = (statement as any).limit?.value?.[0]?.value;
          if (typeof limitVal === 'number' && limitVal > params.max_limit) {
            violations.push({
              ruleId,
              packId,
              severity: 'warning',
              message: `LIMIT ${limitVal} exceeds maximum permitted ceiling of ${params.max_limit}.`,
              suggestedFix: `Reduce LIMIT clause to ${params.max_limit} or less.`,
              context: { requestedLimit: limitVal, maxLimit: params.max_limit },
            });
          }
        }
      }
    } catch {
      // Fallback Chain: Regex-based danger detection when SQL dialect AST fails
      const fallbackViolations = this.evaluateRegexFallback(ruleId, packId, params, sql);
      violations.push(...fallbackViolations);
    }

    return violations;
  }

  /**
   * Principled AST Constant-Folding and Predicate Invariant Analysis:
   * Detects whether a WHERE clause is unconditionally true (tautological),
   * lacks row-restricting column references, or compares columns against themselves.
   */
  private isTautologyWhere(whereAst: any, _rawSql: string): boolean {
    if (!whereAst || typeof whereAst !== 'object') {
      return true; // Missing where is unconditional
    }

    // 1. Self column comparison: WHERE id = id or WHERE users.id = users.id
    if (this.isSelfColumnComparison(whereAst)) {
      return true;
    }

    // 2. OR compound expression where either branch is a constant tautology (e.g. WHERE id = 123 OR 1=1)
    if (whereAst.type === 'binary_expr' && String(whereAst.operator).toUpperCase() === 'OR') {
      if (this.isTautologyWhere(whereAst.left, _rawSql) || this.isTautologyWhere(whereAst.right, _rawSql)) {
        return true;
      }
    }

    // 3. Subtree with zero column references -> constant-fold the expression
    if (!this.hasColumnReferences(whereAst)) {
      const folded = this.foldConstantExpression(whereAst);
      if (folded === true) return true;
      if (folded === undefined) {
        // Unresolvable constant expression without column references -> treat as unconstrained
        return true;
      }
    }

    return false;
  }

  private hasColumnReferences(node: any): boolean {
    if (!node || typeof node !== 'object') return false;
    if (node.type === 'column_ref') return true;

    for (const key of Object.keys(node)) {
      if (key === 'table' || key === 'column') continue;
      const val = node[key];
      if (Array.isArray(val)) {
        if (val.some((item) => this.hasColumnReferences(item))) return true;
      } else if (typeof val === 'object' && val !== null) {
        if (this.hasColumnReferences(val)) return true;
      }
    }
    return false;
  }

  private isSelfColumnComparison(node: any): boolean {
    if (!node || typeof node !== 'object') return false;
    if (node.type === 'binary_expr' && node.operator === '=') {
      if (node.left?.type === 'column_ref' && node.right?.type === 'column_ref') {
        const leftCol = String(node.left.column || '').toLowerCase();
        const rightCol = String(node.right.column || '').toLowerCase();
        const leftTab = String(node.left.table || '').toLowerCase();
        const rightTab = String(node.right.table || '').toLowerCase();
        if (leftCol && rightCol && leftCol === rightCol && leftTab === rightTab) {
          return true;
        }
      }
    }
    return false;
  }

  private foldConstantExpression(node: any): unknown {
    if (!node || typeof node !== 'object') return undefined;
    if (node.type === 'number') return Number(node.value);
    if (node.type === 'string' || node.type === 'single_quote_string') return String(node.value);
    if (node.type === 'bool') return Boolean(node.value);
    if (node.type === 'null') return null;

    if (node.type === 'binary_expr') {
      const op = String(node.operator || '').toUpperCase();

      if (op === 'IS') {
        const left = this.foldConstantExpression(node.left);
        const right = this.foldConstantExpression(node.right);
        return left === right;
      }

      if (op === 'IN') {
        const left = this.foldConstantExpression(node.left);
        if (node.right?.type === 'expr_list' && Array.isArray(node.right.value)) {
          const items = node.right.value.map((v: any) => this.foldConstantExpression(v));
          return items.includes(left);
        }
      }

      if (op === 'BETWEEN') {
        const val = this.foldConstantExpression(node.left);
        if (node.right?.type === 'expr_list' && Array.isArray(node.right.value) && node.right.value.length === 2) {
          const min = this.foldConstantExpression(node.right.value[0]);
          const max = this.foldConstantExpression(node.right.value[1]);
          return Number(val) >= Number(min) && Number(val) <= Number(max);
        }
      }

      const left = this.foldConstantExpression(node.left);
      const right = this.foldConstantExpression(node.right);

      switch (op) {
        case '=':
          return left == right; // eslint-disable-line eqeqeq
        case '!=':
        case '<>':
          return left != right; // eslint-disable-line eqeqeq
        case '<':
          return Number(left) < Number(right);
        case '<=':
          return Number(left) <= Number(right);
        case '>':
          return Number(left) > Number(right);
        case '>=':
          return Number(left) >= Number(right);
        case 'AND':
          return Boolean(left) && Boolean(right);
        case 'OR':
          return Boolean(left) || Boolean(right);
      }
    }
    return undefined;
  }

  private extractSqlString(toolCall: ToolCall, customField?: string): string | null {
    if (customField && typeof toolCall.params[customField] === 'string') {
      return toolCall.params[customField] as string;
    }

    // Common SQL parameter field names
    for (const key of ['sql', 'query', 'statement', 'command', 'q']) {
      if (typeof toolCall.params[key] === 'string') {
        return toolCall.params[key] as string;
      }
    }

    return null;
  }

  private evaluateRegexFallback(
    ruleId: string,
    packId: string,
    _params: SqlAstConditionParams,
    sql: string
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];
    const normalized = sql.replace(/\s+/g, ' ').trim();

    if (/\bDROP\s+(TABLE|DATABASE|SCHEMA|VIEW)\b/i.test(normalized)) {
      violations.push({
        ruleId,
        packId,
        severity: 'critical',
        message: `Destructive DROP statement detected via safety fallback filter.`,
        suggestedFix: `Destructive DROP commands are blocked.`,
        context: { fallbackUsed: true, pattern: 'DROP' },
      });
    }

    if (/\bTRUNCATE\s+(TABLE)?\b/i.test(normalized)) {
      violations.push({
        ruleId,
        packId,
        severity: 'critical',
        message: `Destructive TRUNCATE statement detected via safety fallback filter.`,
        suggestedFix: `TRUNCATE is blocked by security policy.`,
        context: { fallbackUsed: true, pattern: 'TRUNCATE' },
      });
    }

    if (/\bALTER\s+TABLE\s+.*\bDROP\b/i.test(normalized)) {
      violations.push({
        ruleId,
        packId,
        severity: 'critical',
        message: `Destructive ALTER TABLE DROP detected via safety fallback filter.`,
        suggestedFix: `Destructive schema modifications are blocked.`,
        context: { fallbackUsed: true, pattern: 'ALTER_DROP' },
      });
    }

    if (
      /\bDELETE\s+FROM\s+[^\s;]+(?:\s*;|\s*$)/i.test(normalized) ||
      /\bDELETE\s+FROM\s+.*\bWHERE\s+(?:1\s*=\s*1|true)\b/i.test(normalized)
    ) {
      violations.push({
        ruleId,
        packId,
        severity: 'critical',
        message: `Mass DELETE statement detected via fallback filter.`,
        suggestedFix: `Add a specific WHERE clause to your DELETE query.`,
        context: { fallbackUsed: true, pattern: 'DELETE_NO_WHERE' },
      });
    }

    return violations;
  }
}
