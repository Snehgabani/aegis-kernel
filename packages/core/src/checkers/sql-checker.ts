import NodeSqlParser from 'node-sql-parser';
import type { AegisViolation, SqlAstConditionParams, ToolCall } from '../types.js';

// Clean ESM/CJS interop for node-sql-parser
const ParserClass: any =
  (NodeSqlParser as any).Parser ??
  (NodeSqlParser as any).default?.Parser ??
  NodeSqlParser;

export class SqlChecker {
  private parser: any;
  private static readonly SUPPORTED_DIALECTS = ['PostgreSQL', 'MySQL', 'SQLite', 'TransactSQL'] as const;

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

    const cleanedSql = SqlChecker.stripSqlComments(sql);

    try {
      // 1. Multi-Dialect AST Parsing (Try PostgreSQL -> MySQL -> SQLite -> TransactSQL)
      const ast = this.parseWithDialects(cleanedSql);
      const astList = Array.isArray(ast) ? ast : [ast];

      for (const statement of astList) {
        if (!statement || typeof statement !== 'object') continue;
        const stmtType = (statement.type ?? '').toUpperCase();

        // Check for mutating statements hidden inside CTEs or subqueries
        const nestedMutations = this.detectNestedMutatingStatements(statement);

        // 1. Block prohibited statement types (including nested in CTEs)
        const allTypes = [stmtType, ...nestedMutations];
        for (const type of allTypes) {
          if (params.block_statements && params.block_statements.includes(type as any)) {
            violations.push({
              ruleId,
              packId,
              severity: 'critical',
              message: `Statement type '${type}' is prohibited by security policy.`,
              suggestedFix: `Avoid using '${type}'. Use read-only queries or specific targeted updates instead.`,
              context: { statementType: type, sql: sql.slice(0, 120) },
            });
          }
        }

        // 2. Detect destructive ALTER TABLE DROP operations
        if (stmtType === 'ALTER' || nestedMutations.includes('ALTER')) {
          const sqlUpper = cleanedSql.toUpperCase();
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

        // 3. Prohibit DELETE without WHERE clause OR with tautological WHERE clause
        if (stmtType === 'DELETE' || nestedMutations.includes('DELETE')) {
          if (params.require === 'WHERE_CLAUSE') {
            const hasWhere = Boolean((statement as any).where);
            const isTautology = this.isTautologyWhere((statement as any).where, cleanedSql);

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
        if (stmtType === 'UPDATE' || nestedMutations.includes('UPDATE')) {
          if (params.require === 'WHERE_CLAUSE') {
            const hasWhere = Boolean((statement as any).where);
            const isTautology = this.isTautologyWhere((statement as any).where, cleanedSql);

            if (!hasWhere || isTautology) {
              violations.push({
                ruleId,
                packId,
                severity: 'critical',
                message: isTautology
                  ? `Mass UPDATE statement detected with tautological WHERE clause (e.g. 1=1).`
                  : `Mass UPDATE statement detected without WHERE clause.`,
                suggestedFix: `Specify target rows with specific predicate conditions (e.g. 'WHERE id = :id').`,
                context: { statementType: 'UPDATE', tautology: isTautology, missing: !hasWhere },
              });
            }
          }
        }

        // 5. Enforce LIMIT ceilings on queries
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
      // Deterministic AST-free token inspection fallback
      const fallbackViolations = this.evaluateRegexFallback(ruleId, packId, params, cleanedSql);
      violations.push(...fallbackViolations);
    }

    return violations;
  }

  private parseWithDialects(sql: string): any {
    for (const dialect of SqlChecker.SUPPORTED_DIALECTS) {
      try {
        return this.parser.astify(sql, { database: dialect });
      } catch {
        // Try next dialect
      }
    }
    // Fallback to default astify
    return this.parser.astify(sql);
  }

  private detectNestedMutatingStatements(ast: any): string[] {
    const mutations: string[] = [];
    if (!ast || typeof ast !== 'object') return mutations;

    // Check Common Table Expressions (CTEs: WITH ... AS (DELETE/UPDATE))
    const withList = ast.with ?? ast._with;
    if (Array.isArray(withList)) {
      for (const cte of withList) {
        if (cte && cte.stmt) {
          const cteType = (cte.stmt.type ?? '').toUpperCase();
          if (['DELETE', 'UPDATE', 'INSERT', 'DROP', 'ALTER', 'TRUNCATE'].includes(cteType)) {
            mutations.push(cteType);
          }
        }
      }
    }

    return mutations;
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
    if (node.type === 'column_ref') {
      // Check if it represents a literal disguised as a column or an actual column
      const colName = this.extractColumnName(node.column);
      return Boolean(colName);
    }

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

  private extractColumnName(col: any): string {
    if (!col) return '';
    if (typeof col === 'string') return col;
    if (typeof col.value === 'string') return col.value;
    if (col.expr && typeof col.expr.value === 'string') return col.expr.value;
    if (col.column && typeof col.column === 'string') return col.column;
    return '';
  }

  private isSelfColumnComparison(node: any): boolean {
    if (!node || typeof node !== 'object') return false;
    if (node.type === 'binary_expr' && node.operator === '=') {
      if (node.left?.type === 'column_ref' && node.right?.type === 'column_ref') {
        const leftCol = this.extractColumnName(node.left.column).toLowerCase();
        const rightCol = this.extractColumnName(node.right.column).toLowerCase();
        const leftTab = this.extractColumnName(node.left.table).toLowerCase();
        const rightTab = this.extractColumnName(node.right.table).toLowerCase();
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

      if (left === undefined || right === undefined) return undefined;

      switch (op) {
        case '=':
        case '==':
          return left === right;
        case '!=':
        case '<>':
          return left !== right;
        case '>':
          return Number(left) > Number(right);
        case '>=':
          return Number(left) >= Number(right);
        case '<':
          return Number(left) < Number(right);
        case '<=':
          return Number(left) <= Number(right);
        case 'AND':
          return Boolean(left) && Boolean(right);
        case 'OR':
          return Boolean(left) || Boolean(right);
      }
    }

    return undefined;
  }

  private extractSqlString(toolCall: ToolCall, databaseField?: string): string | null {
    if (!toolCall.params || typeof toolCall.params !== 'object') {
      return null;
    }

    const params = toolCall.params as Record<string, unknown>;

    // 1. Explicit database_field
    if (databaseField && typeof params[databaseField] === 'string') {
      return params[databaseField] as string;
    }

    // 2. Common top-level SQL field names
    const commonFields = ['sql', 'query', 'statement', 'command', 'q', 'sql_query'];
    for (const field of commonFields) {
      if (typeof params[field] === 'string') {
        return params[field] as string;
      }
    }

    // 3. Nested object extraction
    return this.findNestedSql(params);
  }

  /**
   * Quote-Aware Single-Pass Lexical Comment Stripper.
   * Preserves string literals while removing block and line comments.
   * Also normalizes comment-injected keyword splits (e.g. DE/*...*\/LETE).
   */
  public static stripSqlComments(sql: string): string {
    let result = '';
    let i = 0;
    const len = sql.length;
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inBacktick = false;

    while (i < len) {
      const char = sql[i];
      const nextChar = i + 1 < len ? sql[i + 1] : '';

      // Handle quotes
      if (char === "'" && !inDoubleQuote && !inBacktick) {
        if (inSingleQuote && nextChar === "'") {
          result += "''";
          i += 2;
          continue;
        }
        inSingleQuote = !inSingleQuote;
        result += char;
        i++;
        continue;
      }

      if (char === '"' && !inSingleQuote && !inBacktick) {
        inDoubleQuote = !inDoubleQuote;
        result += char;
        i++;
        continue;
      }

      if (char === '`' && !inSingleQuote && !inDoubleQuote) {
        inBacktick = !inBacktick;
        result += char;
        i++;
        continue;
      }

      // If inside string literal, preserve everything
      if (inSingleQuote || inDoubleQuote || inBacktick) {
        result += char;
        i++;
        continue;
      }

      // Block comment /* ... */ outside quotes
      if (char === '/' && nextChar === '*') {
        i += 2;
        while (i + 1 < len && !(sql[i] === '*' && sql[i + 1] === '/')) {
          i++;
        }
        i += 2; // skip */
        result += ' ';
        continue;
      }

      // Line comment -- ... outside quotes
      if (char === '-' && nextChar === '-') {
        i += 2;
        while (i < len && sql[i] !== '\n' && sql[i] !== '\r') {
          i++;
        }
        result += ' ';
        continue;
      }

      result += char;
      i++;
    }

    let cleaned = result.replace(/\s+/g, ' ').trim();
    // Normalize comment-injected keyword splits (e.g. DEL/**/ETE -> DELETE, D R O P -> DROP)
    cleaned = cleaned
      .replace(/\bD\s*E\s*L\s*E\s*T\s*E\b/gi, 'DELETE')
      .replace(/\bD\s*R\s*O\s*P\b/gi, 'DROP')
      .replace(/\bT\s*R\s*U\s*N\s*C\s*A\s*T\s*E\b/gi, 'TRUNCATE')
      .replace(/\bU\s*P\s*D\s*A\s*T\s*E\b/gi, 'UPDATE')
      .replace(/\bA\s*L\s*T\s*E\s*R\b/gi, 'ALTER')
      .replace(/\bI\s*N\s*S\s*E\s*R\s*T\b/gi, 'INSERT')
      .replace(/\bS\s*E\s*L\s*E\s*C\s*T\b/gi, 'SELECT');

    return cleaned;
  }

  private findNestedSql(obj: unknown, visited: Set<unknown> = new Set()): string | null {
    if (!obj || typeof obj !== 'object' || visited.has(obj)) return null;
    visited.add(obj);
    const record = obj as Record<string, unknown>;

    for (const key of ['sql', 'query', 'statement', 'command', 'q', 'sql_query']) {
      if (typeof record[key] === 'string') {
        return record[key] as string;
      }
    }

    for (const val of Object.values(record)) {
      if (val && typeof val === 'object') {
        const found = this.findNestedSql(val, visited);
        if (found) return found;
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
    const rawTokens = sql.toUpperCase().split(/\s+/).filter(Boolean);
    const tokens = rawTokens.map((t) => (t.endsWith(';') ? t.slice(0, -1) : t));

    // 1. Comprehensive DDL Detection
    const dropIdx = tokens.indexOf('DROP');
    if (dropIdx !== -1 && dropIdx + 1 < tokens.length) {
      const next = tokens[dropIdx + 1];
      const prohibitedTargets = [
        'TABLE', 'DATABASE', 'SCHEMA', 'VIEW', 'INDEX',
        'PROCEDURE', 'FUNCTION', 'TRIGGER', 'USER', 'ROLE',
        'EXTENSION', 'MATERIALIZED'
      ];
      if (prohibitedTargets.includes(next)) {
        violations.push({
          ruleId,
          packId,
          severity: 'critical',
          message: `Destructive DROP statement detected via safety fallback filter.`,
          suggestedFix: `Destructive DROP commands are blocked.`,
          context: { fallbackUsed: true, pattern: `DROP ${next}` },
        });
      }
    }

    // 2. TRUNCATE
    if (tokens.includes('TRUNCATE')) {
      violations.push({
        ruleId,
        packId,
        severity: 'critical',
        message: `Destructive TRUNCATE statement detected via safety fallback filter.`,
        suggestedFix: `TRUNCATE is blocked by security policy.`,
        context: { fallbackUsed: true, pattern: 'TRUNCATE' },
      });
    }

    // 3. ALTER TABLE ... DROP
    const alterIdx = tokens.indexOf('ALTER');
    const alterTableIdx = alterIdx !== -1 && tokens[alterIdx + 1] === 'TABLE' ? alterIdx : -1;
    if (alterTableIdx !== -1) {
      const remaining = tokens.slice(alterTableIdx + 2);
      if (remaining.includes('DROP')) {
        violations.push({
          ruleId,
          packId,
          severity: 'critical',
          message: `Destructive ALTER TABLE DROP detected via safety fallback filter.`,
          suggestedFix: `Destructive schema modifications are blocked.`,
          context: { fallbackUsed: true, pattern: 'ALTER_DROP' },
        });
      }
    }

    // 4. DELETE without WHERE or with tautology
    const deleteIdx = tokens.indexOf('DELETE');
    if (deleteIdx !== -1) {
      const whereIdx = tokens.indexOf('WHERE', deleteIdx);
      if (whereIdx === -1) {
        violations.push({
          ruleId,
          packId,
          severity: 'critical',
          message: `Mass DELETE statement detected via fallback filter.`,
          suggestedFix: `Add a specific WHERE clause to your DELETE query.`,
          context: { fallbackUsed: true, pattern: 'DELETE_NO_WHERE' },
        });
      } else {
        const whereClause = tokens.slice(whereIdx + 1).join(' ');
        const tautologies = [
          '1=1', '1 = 1', '2=2', '2 = 2', '0=0', '0 = 0',
          "'A'='A'", "'A' = 'A'", "'1'='1'", "'1' = '1'",
          'TRUE', '1<2', '1 < 2', 'NULL IS NULL'
        ];
        if (tautologies.some((t) => whereClause === t || whereClause.startsWith(t + ' ') || whereClause.includes('OR 1=1'))) {
          violations.push({
            ruleId,
            packId,
            severity: 'critical',
            message: `Mass DELETE statement detected via fallback filter with tautological condition.`,
            suggestedFix: `Add a specific targeted WHERE clause to your DELETE query.`,
            context: { fallbackUsed: true, pattern: 'DELETE_TAUTOLOGY' },
          });
        }
      }
    }

    return violations;
  }
}
