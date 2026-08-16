import NodeSqlParser from 'node-sql-parser';
import type { AegisSeverity, AegisViolation, SqlAstConditionParams, ToolCall } from '../types.js';

// Clean ESM/CJS interop for node-sql-parser
const ParserClass: any =
  (NodeSqlParser as any).Parser ??
  (NodeSqlParser as any).default?.Parser ??
  NodeSqlParser;

const HOMOGLYPH_DECODE_MAP: Record<string, string> = {
  '\u0430': 'a', '\u0410': 'A',
  '\u0432': 'b', '\u0412': 'B',
  '\u0441': 'c', '\u0421': 'C',
  '\u0435': 'e', '\u0415': 'E',
  '\u0456': 'i', '\u0406': 'I',
  '\u0458': 'j', '\u0408': 'J',
  '\u043A': 'k', '\u041A': 'K',
  '\u041C': 'M',
  '\u041D': 'H',
  '\u043E': 'o', '\u041E': 'O',
  '\u0440': 'p', '\u0420': 'P',
  '\u0455': 's', '\u0405': 'S',
  '\u0422': 'T',
  '\u0443': 'y',
  '\u0445': 'x', '\u0425': 'X',
  '\u0391': 'A', '\u03B1': 'a',
  '\u0392': 'B',
  '\u0395': 'E', '\u03B5': 'e',
  '\u039F': 'O', '\u03BF': 'o',
  '\u03A1': 'P', '\u03C1': 'p',
  '\u03A4': 'T',
  '\u03A7': 'X', '\u03C7': 'x',
};

export class SqlChecker {
  private parser: any;
  private static readonly SUPPORTED_DIALECTS = ['PostgreSQL', 'MySQL', 'SQLite', 'TransactSQL'] as const;

  private static readonly DEFAULT_SQL_TOOLS = new Set([
    'database_exec', 'execute_sql', 'exec_sql', 'run_sql', 'run_query',
    'sql_query', 'query_database', 'query_db', 'db_query', 'mysql_query',
    'postgres_query', 'sqlite_query', 'tsql_query', 'database_query',
    'query_sql', 'sql', 'sql_exec', 'execute_query', 'exec_query',
    'db_exec', 'sqlite_exec', 'query',
  ]);

  private static readonly SQL_TOOL_HINTS = ['sql', 'database', 'db_', '_db', 'dbquery', 'query_exec'];

  constructor() {
    this.parser = new ParserClass();
  }

  public evaluate(
    ruleId: string,
    packId: string,
    params: SqlAstConditionParams,
    toolCall: ToolCall
  , severity: AegisSeverity = 'critical'
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];
    const sql = this.extractSqlString(toolCall, params.database_field);

    if (!sql || typeof sql !== 'string' || !sql.trim()) {
      return violations;
    }

    // SECURITY: normalize BEFORE comment stripping / parsing / fallback.
    // Without this, zero-width, bidi and fullwidth-unicode characters inside
    // SQL keywords (D<ZW>ELETE, ＤＥＬＥＴＥ) defeat BOTH the AST parser and
    // the regex fallback, turning destructive SQL into an ALLOWED verdict.
    const normalizedSql = SqlChecker.normalizeUnicode(sql);
    const cleanedSql = SqlChecker.stripSqlComments(normalizedSql);

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
              severity,
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
              severity,
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
                severity,
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
                severity,
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
              severity,
              message: `LIMIT ${limitVal} exceeds maximum permitted ceiling of ${params.max_limit}.`,
              suggestedFix: `Reduce LIMIT clause to ${params.max_limit} or less.`,
              context: { requestedLimit: limitVal, maxLimit: params.max_limit },
            });
          }
        }
      }
    } catch {
      // Deterministic AST-free token inspection fallback
      const fallbackViolations = this.evaluateRegexFallback(ruleId, packId, params, cleanedSql, severity);
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

    // 1b. Unconditional NULL test: WHERE id IS NOT NULL matches every row
    //     whose column is non-null (effectively an unconstrained mass delete).
    //     WHERE x IS NULL is NOT flagged (it only matches NULL rows).
    if (
      whereAst.type === 'binary_expr' &&
      String(whereAst.operator).toUpperCase() === 'IS NOT' &&
      whereAst.right?.type === 'null'
    ) {
      return true;
    }

    // 2. OR compound expression where either branch is a constant tautology (e.g. WHERE id = 123 OR 1=1)
    if (whereAst.type === 'binary_expr' && String(whereAst.operator).toUpperCase() === 'OR') {
      if (this.isTautologyWhere(whereAst.left, _rawSql) || this.isTautologyWhere(whereAst.right, _rawSql)) {
        return true;
      }
    }

    // 3. Subtree with zero column references -> constant-fold the expression (catches WHERE 1, WHERE 1=1, WHERE 2>1)
    if (!this.hasColumnReferences(whereAst)) {
      const folded = this.foldConstantExpression(whereAst);
      if (folded === true || (typeof folded === 'number' && folded !== 0) || folded === '1') return true;
      if (folded === undefined) {
        // Unresolvable constant expression without column references -> treat as unconstrained
        return true;
      }
    }

    // 4. Domain lower-bound tautologies on identifiers: WHERE id > 0, WHERE id >= 0, WHERE id != -1, WHERE id <> -1
    if (whereAst.type === 'binary_expr') {
      const op = String(whereAst.operator).toUpperCase();
      const leftIsCol = whereAst.left?.type === 'column_ref';
      const rightIsCol = whereAst.right?.type === 'column_ref';

      if (leftIsCol && whereAst.right?.type === 'number') {
        const numVal = Number(whereAst.right.value);
        if ((op === '>' && numVal <= 0) || (op === '>=' && numVal <= 1) || ((op === '<>' || op === '!=') && numVal < 0)) {
          return true;
        }
      } else if (rightIsCol && whereAst.left?.type === 'number') {
        const numVal = Number(whereAst.left.value);
        if ((op === '<' && numVal <= 0) || (op === '<=' && numVal <= 1) || ((op === '<>' || op === '!=') && numVal < 0)) {
          return true;
        }
      }

      // 5. Self-referential unconstrained subquery: WHERE id IN (SELECT id FROM same_table)
      if (op === 'IN') {
        if (whereAst.right?.type === 'expr_list' && Array.isArray(whereAst.right.value)) {
          for (const item of whereAst.right.value) {
            const subAst = item?.ast || item;
            if (subAst && typeof subAst === 'object' && (subAst.type === 'select' || subAst._type === 'select')) {
              if (!subAst.where) {
                return true;
              }
            }
          }
        }
        const rightSubquery = whereAst.right?.ast || whereAst.right;
        if (rightSubquery && typeof rightSubquery === 'object' && (rightSubquery.type === 'select' || rightSubquery._type === 'select')) {
          if (!rightSubquery.where) {
            return true;
          }
        }
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

  private extractColumnName(column: any): string | null {
    if (!column) return null;
    if (typeof column === 'string') return column;
    if (typeof column === 'object') {
      if (column.expr && column.expr.value) {
        return String(column.expr.value);
      }
      if (column.value) {
        return String(column.value);
      }
    }
    return null;
  }

  private isSelfColumnComparison(node: any): boolean {
    if (!node || typeof node !== 'object') return false;
    if (node.type === 'binary_expr' && ['=', '==', '<=', '>='].includes(node.operator)) {
      if (node.left?.type === 'column_ref' && node.right?.type === 'column_ref') {
        const leftCol = this.extractColumnName(node.left.column);
        const rightCol = this.extractColumnName(node.right.column);
        const leftTable = node.left.table || '';
        const rightTable = node.right.table || '';
        if (leftCol && rightCol && leftCol.toLowerCase() === rightCol.toLowerCase() && leftTable.toLowerCase() === rightTable.toLowerCase()) {
          return true;
        }
      }
    }
    return false;
  }

  private foldConstantExpression(node: any): boolean | number | string | null | undefined {
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

  public static readonly LOOKS_LIKE_SQL_REGEX =
    /^\s*(?:--[^\n]*\n|\/\*[\s\S]*?\*\/|\s*)*(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|EXEC|EXECUTE|GRANT|REVOKE|WITH|MERGE|CALL|REPLACE|BEGIN|COMMIT|ROLLBACK)\b/i;

  /**
   * SQL tool gate: checks whether tool name represents database execution.
   */
  public static isSqlTool(tool: string): boolean {
    const t = (tool || '').toLowerCase();
    if (SqlChecker.DEFAULT_SQL_TOOLS.has(t)) return true;
    return SqlChecker.SQL_TOOL_HINTS.some((h) => t.includes(h));
  }

  /** Param names that are unambiguously SQL, even on generic tool names. */
  public static isExplicitSqlField(field: string): boolean {
    const f = (field || '').toLowerCase().replace(/[^a-z0-9_]/g, '');
    return (
      f === 'sql' ||
      f === 'sql_query' ||
      f === 'sqlquery' ||
      f === 'sql_statement' ||
      f === 'sqltext' ||
      f === 'sql_text' ||
      f === 'stmt' ||
      f === 'sql_stmt' ||
      f === 'database_query' ||
      f === 'query_sql' ||
      f === 'raw_sql' ||
      f === 'db_query'
    );
  }

  public static readonly SEARCH_TOOL_NAMES = new Set([
    'search_kb', 'kb_search', 'web_search', 'google_search', 'docs_search',
    'doc_search', 'search_docs', 'wiki_search', 'semantic_search', 'search_wiki',
    'search_documentation', 'search_articles', 'help_search', 'faq_search'
  ]);

  public static isSearchTool(tool: string): boolean {
    const t = (tool || '').toLowerCase();
    return SqlChecker.SEARCH_TOOL_NAMES.has(t);
  }

  private extractSqlString(toolCall: ToolCall, databaseField?: string): string | null {
    if (!toolCall.params || typeof toolCall.params !== 'object') {
      return null;
    }

    const params = toolCall.params as Record<string, unknown>;
    const tool = toolCall.tool ?? '';

    // 1. Explicit database_field (rule-configured) always wins.
    if (databaseField && typeof params[databaseField] === 'string') {
      return params[databaseField] as string;
    }

    // 2. Comprehensive Fail-Closed SQL Extraction across all tools
    return this.findSqlInParams(params, tool);
  }

  private findSqlInParams(params: Record<string, unknown>, tool: string, depth = 0): string | null {
    if (depth > 6) return null;
    const isDbTool = SqlChecker.isSqlTool(tool);
    const isSearch = SqlChecker.isSearchTool(tool);

    // Check common high-priority fields first
    const commonFields = [
      'sql', 'stmt', 'sql_query', 'sql_statement', 'raw_sql', 'sql_stmt', 'query_sql', 'db_query',
      'query', 'statement', 'command', 'cmd', 'body', 'text', 'script', 'expression', 'code', 'q'
    ];

    for (const field of commonFields) {
      if (typeof params[field] === 'string') {
        const val = params[field] as string;
        if (SqlChecker.isExplicitSqlField(field)) {
          return val;
        }
        if (isSearch && (field === 'query' || field === 'q')) {
          continue; // Search tools with query params are search terms, not SQL
        }
        if (SqlChecker.LOOKS_LIKE_SQL_REGEX.test(val) || (isDbTool && val.trim().length > 0)) {
          return val;
        }
      }
    }

    // Recursive search across all fields and sub-objects
    for (const [key, value] of Object.entries(params)) {
      if (typeof value === 'string') {
        if (isSearch && (key === 'query' || key === 'q')) {
          continue; // Search tools with query params are search terms, not SQL
        }
        if (SqlChecker.isExplicitSqlField(key) || SqlChecker.LOOKS_LIKE_SQL_REGEX.test(value)) {
          return value;
        }
      } else if (value && typeof value === 'object' && !Array.isArray(value)) {
        const found = this.findSqlInParams(value as Record<string, unknown>, tool, depth + 1);
        if (found) return found;
      } else if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string' && SqlChecker.LOOKS_LIKE_SQL_REGEX.test(item)) {
            return item;
          } else if (item && typeof item === 'object') {
            const found = this.findSqlInParams(item as Record<string, unknown>, tool, depth + 1);
            if (found) return found;
          }
        }
      }
    }

    return null;
  }

  /**
   * Quote-Aware Single-Pass Lexical Comment Stripper.
   * Preserves string literals while removing block and line comments.
   * Also normalizes comment-injected keyword splits (e.g. DE/*...*\/LETE).
   */

  /**
   * Normalize unicode representation to prevent evasion via:
   * 1. Compatibility decomposition (NFKD) -> fullwidth (0xFF01-0xFF5E) mapped to ASCII
   * 2. Cyrillic & Greek homoglyph decoding to ASCII
   * 3. Stripping of zero-width spaces (U+200B..U+200D), word joiner
   *    (U+2060), and soft hyphen (U+00AD).
   */
  public static normalizeUnicode(sql: string): string {
    let normalized = sql
      .normalize('NFKD')
      .replace(/[\u200b-\u200d\u2060\u2061\u2062\u2063\u2064\u200e\u200f\u202a-\u202e\uFEFF\u00ad]/g, '');

    // Decode homoglyphs
    let decoded = '';
    for (const ch of normalized) {
      decoded += HOMOGLYPH_DECODE_MAP[ch] ?? ch;
    }
    return decoded;
  }

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

  private evaluateRegexFallback(
    ruleId: string,
    packId: string,
    _params: SqlAstConditionParams,
    sql: string,
    severity: AegisSeverity = 'critical'
  ): AegisViolation[] {
    let processedSql = sql;

    // 1. Hex (\xXX, 0xXX) & URL (%XX) decoding
    processedSql = processedSql.replace(/0x([0-9a-fA-F]+)/g, (match, hex) => {
      try {
        return Buffer.from(hex, 'hex').toString('utf8');
      } catch {
        return match;
      }
    });
    processedSql = processedSql.replace(/\\x([0-9a-fA-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
    processedSql = processedSql.replace(/%([0-9a-fA-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));

    // 1b. Base64 encoded payload detection in SQL string
    processedSql = processedSql.replace(/\b[A-Za-z0-9+/]{12,}={0,2}\b/g, (match) => {
      try {
        const rawDecoded = Buffer.from(match, 'base64').toString('utf8');
        const decoded = SqlChecker.normalizeUnicode(rawDecoded).replace(/\/\*.*?\*\//g, '');
        if (/\b(DELETE|DROP|TRUNCATE|UPDATE|ALTER|SELECT)\b/i.test(decoded)) {
          return decoded;
        }
      } catch {}
      return match;
    });

    // 2. String concatenation detection
    let prev;
    do {
      prev = processedSql;
      processedSql = processedSql.replace(/'([^']*)'\s*\|\|\s*'([^']*)'/g, "'$1$2'");
      processedSql = processedSql.replace(/CONCAT\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)/gi, "'$1$2'");
    } while (processedSql !== prev);
    
    // Unquote fully concatenated SQL keywords so they can match tokens
    processedSql = processedSql.replace(/'(DROP|DELETE|UPDATE|TRUNCATE|ALTER|TABLE|DATABASE|SCHEMA|VIEW)'/gi, '$1');

    // 3. Inline comment splitting detection
    processedSql = processedSql.replace(/\/\*.*?\*\//g, '');

    const violations: AegisViolation[] = [];
    const rawTokens = processedSql.toUpperCase().split(/\s+/).filter(Boolean);
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
          severity,
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
        severity,
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
          severity,
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
          severity,
          message: `Mass DELETE statement detected via fallback filter.`,
          suggestedFix: `Add a specific WHERE clause to your DELETE query.`,
          context: { fallbackUsed: true, pattern: 'DELETE_NO_WHERE' },
        });
      } else {
        const whereClause = tokens.slice(whereIdx + 1).join(' ');
        
        // Comprehensive fallback tautology check: N=N, 'X'='X', N>M, IS NOT NULL, TRUE, 1, id>0, id<>-1, subqueries
        const isTautology = 
          whereClause === 'TRUE' ||
          whereClause === '1' ||
          whereClause.startsWith('TRUE') ||
          whereClause.startsWith('1 ') ||
          /\bIS\s+NOT\s+NULL\b/i.test(whereClause) ||
          /(\d+)\s*=\s*\1\b/.test(whereClause) ||
          /(\d+)\s*!=\s*(\d+)/.test(whereClause) ||
          /'([^']+)'\s*=\s*'\1'/i.test(whereClause) ||
          /\b[a-zA-Z_]\w*\s*>\s*0\b/i.test(whereClause) ||
          /\b[a-zA-Z_]\w*\s*(?:<>|!=)\s*-\d+\b/i.test(whereClause) ||
          /\bIN\s*\(\s*SELECT\b/i.test(whereClause) ||
          /\bOR\s+(?:1\s*=\s*1|TRUE|1|\d+\s*>\s*\d+|'[^']+'\s*=\s*'[^']+')/i.test(whereClause) ||
          ['1=1', '1 = 1', '2=2', '2 = 2', '0=0', '0 = 0', '100=100', '100 = 100', '2>1', '2 > 1', '1'].some(
            t => whereClause === t || whereClause.startsWith(t + ' ') || whereClause.includes(t)
          );

        if (isTautology) {
          violations.push({
            ruleId,
            packId,
            severity,
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
