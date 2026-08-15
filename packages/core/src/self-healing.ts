/**
 * @file packages/core/src/self-healing.ts
 * @description Self-Healing Agent Proposal Synthesizer & Canonical Correction Generator.
 */

export interface SqlFixRequest {
  rawQuery: string;
  tenantId?: string;
  blockedReason: string;
}

export interface SqlFixProposal {
  canSelfHeal: boolean;
  suggestedQuery?: string;
  explanation: string;
}

export interface NumericFixRequest {
  originalAmount: number;
  maxAllowed: number;
  currency?: string;
}

export interface NumericFixProposal {
  canSelfHeal: boolean;
  suggestedAmount: number;
  explanation: string;
}

export class SelfHealingProposalSynthesizer {
  /**
   * Analyzes an invalid SQL tool proposal and synthesizes a safe, canonical mutation.
   */
  public synthesizeSqlFix(request: SqlFixRequest): SqlFixProposal {
    const trimmed = request.rawQuery.trim();

    // Fix 1: Missing WHERE on DELETE
    if (/^DELETE\s+FROM\s+([a-zA-Z0-9_]+)$/i.test(trimmed)) {
      const match = trimmed.match(/^DELETE\s+FROM\s+([a-zA-Z0-9_]+)$/i);
      const tableName = match ? match[1] : 'table';
      const tenantClause = request.tenantId ? ` WHERE tenant_id = '${request.tenantId}' AND id = :target_id` : ` WHERE id = :target_id`;
      return {
        canSelfHeal: true,
        suggestedQuery: `DELETE FROM ${tableName}${tenantClause}`,
        explanation: 'Enforced explicit primary-key identifier in WHERE clause to prevent accidental table-wide data loss.'
      };
    }

    // Fix 2: Missing WHERE on UPDATE
    if (/^UPDATE\s+([a-zA-Z0-9_]+)\s+SET\s+(.+)$/i.test(trimmed) && !/WHERE/i.test(trimmed)) {
      const match = trimmed.match(/^UPDATE\s+([a-zA-Z0-9_]+)\s+SET\s+(.+)$/i);
      const tableName = match ? match[1] : 'table';
      const setClause = match ? match[2] : '';
      const tenantClause = request.tenantId ? ` WHERE tenant_id = '${request.tenantId}' AND id = :target_id` : ` WHERE id = :target_id`;
      return {
        canSelfHeal: true,
        suggestedQuery: `UPDATE ${tableName} SET ${setClause}${tenantClause}`,
        explanation: 'Enforced WHERE clause targeting specific row ID to prevent unconditional batch modification.'
      };
    }

    return {
      canSelfHeal: false,
      explanation: `Query violation requires human or policy redesign: ${request.blockedReason}`
    };
  }

  /**
   * Synthesizes a safe clamped parameter value for numeric overspend violations.
   */
  public synthesizeNumericFix(request: NumericFixRequest): NumericFixProposal {
    if (request.originalAmount > request.maxAllowed) {
      return {
        canSelfHeal: true,
        suggestedAmount: request.maxAllowed,
        explanation: `Clamped to maximum authorized threshold of ${request.maxAllowed} ${request.currency ?? 'USD'}.`
      };
    }

    return {
      canSelfHeal: false,
      suggestedAmount: request.originalAmount,
      explanation: 'Amount is within allowable threshold.'
    };
  }
}
