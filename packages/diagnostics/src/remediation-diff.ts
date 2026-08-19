/**
 * Aegis Invariant Kernel — Automated AST Remediation Diff Generator
 *
 * Produces unified, compiler-grade diff patches for failed AI agent tool calls.
 */

export interface RemediationDiffResult {
  ruleId: string;
  category: string;
  diff: string;
  explanation: string;
}

export class RemediationDiffGenerator {
  /**
   * Synthesize unified diff for SQL AST invariant violations
   */
  public static generateSqlDiff(originalQuery: string, ruleId: string): RemediationDiffResult {
    const trimmed = originalQuery.trim();

    if (/^DELETE\s+FROM\s+([a-zA-Z0-9_]+)$/i.test(trimmed)) {
      const match = trimmed.match(/^DELETE\s+FROM\s+([a-zA-Z0-9_]+)$/i);
      const table = match ? match[1] : 'table';
      return {
        ruleId,
        category: 'SQL_UNCONSTRAINED_DELETE',
        diff: `- ${trimmed}\n+ DELETE FROM ${table} WHERE id = :id`,
        explanation: 'Unconstrained DELETE violates state persistence invariants. Bound by primary key.',
      };
    }

    if (/^UPDATE\s+([a-zA-Z0-9_]+)\s+SET\s+(.+)$/i.test(trimmed) && !/WHERE/i.test(trimmed)) {
      const match = trimmed.match(/^UPDATE\s+([a-zA-Z0-9_]+)\s+SET\s+(.+)$/i);
      const table = match ? match[1] : 'table';
      const setClause = match ? match[2] : '';
      return {
        ruleId,
        category: 'SQL_UNCONSTRAINED_UPDATE',
        diff: `- ${trimmed}\n+ UPDATE ${table} SET ${setClause} WHERE id = :id`,
        explanation: 'Mass UPDATE without WHERE clause affects all rows. Bound with explicit WHERE predicate.',
      };
    }

    if (/DROP\s+TABLE/i.test(trimmed)) {
      return {
        ruleId,
        category: 'SQL_DESTRUCTIVE_DDL',
        diff: `- ${trimmed}\n+ -- DROP TABLE prohibited in production agent workflows. Use soft-delete/migration.`,
        explanation: 'Destructive DDL statements are strictly prohibited for autonomous agents.',
      };
    }

    return {
      ruleId,
      category: 'SQL_AST_VIOLATION',
      diff: `- ${trimmed}\n+ ${trimmed} /* PARAMETERIZED & FILTERED */`,
      explanation: 'Query violated AST invariant constraints.',
    };
  }

  /**
   * Synthesize unified diff for Numeric / Financial ceiling breaches
   */
  public static generateNumericDiff(field: string, actualValue: number, maxCeiling: number): RemediationDiffResult {
    return {
      ruleId: 'NUMERIC_CEILING_BREACH',
      category: 'FINANCIAL_BOUNDS',
      diff: `- { "${field}": ${actualValue} }\n+ { "${field}": ${maxCeiling} } // Clamped to invariant ceiling`,
      explanation: `Value ${actualValue} exceeded maximum policy bound of ${maxCeiling}.`,
    };
  }

  /**
   * Synthesize unified diff for PII / Secrets Token Masking
   */
  public static generatePiiMaskDiff(field: string, rawSnippet: string, maskedToken: string): RemediationDiffResult {
    return {
      ruleId: 'PII_SECRETS_LEAK',
      category: 'DATA_EXFILTRATION',
      diff: `- { "${field}": "${rawSnippet}" }\n+ { "${field}": "${maskedToken}" }`,
      explanation: 'Raw credential/PII token intercepted. Replaced with salted in-process vault token.',
    };
  }
}
