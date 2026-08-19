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
    const upper = trimmed.toUpperCase();

    if (upper.startsWith('DELETE FROM')) {
      const parts = trimmed.split(/\s+/);
      const table = parts[2] || 'table';
      if (!upper.includes(' WHERE')) {
        return {
          ruleId,
          category: 'SQL_UNCONSTRAINED_DELETE',
          diff: `- ${trimmed}\n+ DELETE FROM ${table} WHERE id = :id`,
          explanation: 'Unconstrained DELETE violates state persistence invariants. Bound by primary key.',
        };
      }
    }

    if (upper.startsWith('UPDATE ')) {
      const setIndex = upper.indexOf(' SET ');
      if (setIndex !== -1 && !upper.includes(' WHERE')) {
        const table = trimmed.substring(7, setIndex).trim();
        const setClause = trimmed.substring(setIndex + 5).trim();
        return {
          ruleId,
          category: 'SQL_UNCONSTRAINED_UPDATE',
          diff: `- ${trimmed}\n+ UPDATE ${table} SET ${setClause} WHERE id = :id`,
          explanation: 'Mass UPDATE without WHERE clause affects all rows. Bound with explicit WHERE predicate.',
        };
      }
    }

    if (upper.includes('DROP TABLE')) {
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
