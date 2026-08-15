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
    // 1. Strip comments
    let normalized = request.rawQuery.replace(/--.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    
    // 2. Whitespace normalization
    normalized = normalized.replace(/\s+/g, ' ').trim();
    
    // 3. Reject complex UPDATE with JOIN
    if (/^UPDATE\s/i.test(normalized) && /\sJOIN\s/i.test(normalized)) {
      return this.synthesizeGenericFix(request);
    }
    
    const tableRegex = /((?:(?:[a-zA-Z0-9_]+|["`][a-zA-Z0-9_]+["`])\.)?(?:[a-zA-Z0-9_]+|["`][a-zA-Z0-9_]+["`]))/;

    // Fix 1: Missing WHERE on DELETE
    const deleteRegex = new RegExp(`^DELETE\\s+FROM\\s+${tableRegex.source}$`, 'i');
    if (deleteRegex.test(normalized)) {
      const match = normalized.match(deleteRegex);
      const tableName = match ? match[1] : 'table';
      const tenantClause = request.tenantId ? ` WHERE tenant_id = '${request.tenantId}' AND id = :target_id` : ` WHERE id = :target_id`;
      return {
        canSelfHeal: true,
        suggestedQuery: `DELETE FROM ${tableName}${tenantClause}`,
        explanation: 'Enforced explicit primary-key identifier in WHERE clause to prevent accidental table-wide data loss.'
      };
    }

    // Fix 2: Missing WHERE on UPDATE
    const updateRegex = new RegExp(`^UPDATE\\s+${tableRegex.source}\\s+SET\\s+(.+)$`, 'i');
    if (updateRegex.test(normalized) && !/WHERE/i.test(normalized)) {
      const match = normalized.match(updateRegex);
      const tableName = match ? match[1] : 'table';
      const setClause = match ? match[2] : '';
      const tenantClause = request.tenantId ? ` WHERE tenant_id = '${request.tenantId}' AND id = :target_id` : ` WHERE id = :target_id`;
      return {
        canSelfHeal: true,
        suggestedQuery: `UPDATE ${tableName} SET ${setClause}${tenantClause}`,
        explanation: 'Enforced WHERE clause targeting specific row ID to prevent unconditional batch modification.'
      };
    }

    return this.synthesizeGenericFix(request);
  }

  public synthesizeGenericFix(request: SqlFixRequest): SqlFixProposal {
    return {
      canSelfHeal: false,
      explanation: `Query violation requires human or policy redesign: ${request.blockedReason}. Complex queries such as those with JOINs or unsupported patterns cannot be safely auto-healed.`
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
