/**
 * @file packages/core/src/explainability.ts
 * @description EU AI Act (Article 13) & NIST AI 600-1 Human-in-the-Loop Explainability Engine.
 * Converts raw AST & parameter violations into plain-English, transparent explanations
 * with mapped regulatory standards and concrete remediation steps.
 */

import type { AegisVerdict, ToolCall } from './types.js';

export interface ViolationExplanation {
  ruleId: string;
  packId: string;
  severity: 'critical' | 'warning' | 'info';
  plainEnglishSummary: string;
  regulatoryStandard: string;
  riskCategory: string;
  suggestedRemediation: string;
}

export interface HumanExplanationReport {
  tool: string;
  allowed: boolean;
  verdictSummary: string;
  latencyMs: number;
  explanations: ViolationExplanation[];
  complianceStatement: string;
}

/**
 * Maps common rule IDs and patterns to human-readable explanations and legal standards.
 */
export function generateHumanExplanation(
  toolCall: ToolCall,
  verdict: AegisVerdict
): HumanExplanationReport {
  if (verdict.allowed) {
    return {
      tool: toolCall.tool,
      allowed: true,
      verdictSummary: `✅ The tool invocation '${toolCall.tool}' is mathematically safe and satisfies all security invariants.`,
      latencyMs: verdict.latencyMs,
      explanations: [],
      complianceStatement: 'Compliant with EU AI Act Article 15 (Cybersecurity & Robustness) and NIST AI RMF MANAGE-1.3.',
    };
  }

  const explanations: ViolationExplanation[] = verdict.violations.map((violation) => {
    let plainEnglishSummary = violation.message;
    let regulatoryStandard = 'OWASP Top 10 for LLM: LLM05 (Improper Output Handling)';
    let riskCategory = 'System Integrity & Access Control';
    let suggestedRemediation = violation.suggestedFix || 'Modify the tool arguments to satisfy the invariant rule.';

    const ruleUpper = violation.ruleId.toUpperCase();
    const msgUpper = violation.message.toUpperCase();

    if (ruleUpper.includes('DROP') || msgUpper.includes('DROP')) {
      plainEnglishSummary = 'The agent attempted to permanently delete a database table structure (DROP TABLE).';
      regulatoryStandard = 'SOC 2 Type II (PI1.1 Processing Integrity) & OWASP ASI05 (Unexpected Code Execution)';
      riskCategory = 'Catastrophic Data Destruction';
      suggestedRemediation = 'Use SELECT queries or scoped UPDATE operations instead of dropping database schemas.';
    } else if (ruleUpper.includes('DELETE') || msgUpper.includes('DELETE')) {
      plainEnglishSummary = 'The agent attempted to delete database rows without specifying a WHERE clause filter.';
      regulatoryStandard = 'SOC 2 Type II (CC6.6 Boundary Protection) & ISO 42001 A.6.2.7';
      riskCategory = 'Mass Data Loss';
      suggestedRemediation = 'Add a restrictive WHERE clause with specific identifier bounds (e.g. WHERE id = ?).';
    } else if (ruleUpper.includes('FIN') || ruleUpper.includes('AMOUNT') || msgUpper.includes('LIMIT') || msgUpper.includes('AMOUNT')) {
      plainEnglishSummary = 'The requested financial transaction exceeds the maximum allowable automated threshold.';
      regulatoryStandard = 'EU AI Act Article 14 (Human Oversight) & OWASP ASI03 (Privilege Abuse)';
      riskCategory = 'Financial Overdraft / Denial of Wallet';
      suggestedRemediation = 'Request step-up human authorization (HITL) or reduce the transaction amount to within policy limits.';
    } else if (ruleUpper.includes('PII') || ruleUpper.includes('DATA') || msgUpper.includes('CREDENTIAL') || msgUpper.includes('PII')) {
      plainEnglishSummary = 'Sensitive Personally Identifiable Information (PII) or secrets were detected in the parameters.';
      regulatoryStandard = 'GDPR Article 32, HIPAA Security Rule & OWASP LLM02 (Sensitive Information Disclosure)';
      riskCategory = 'Privacy Breach / Data Exfiltration';
      suggestedRemediation = 'Sanitize the payload by masking credit card numbers, SSNs, or secret keys before calling the tool.';
    } else if (ruleUpper.includes('RBAC') || ruleUpper.includes('IDENTITY') || msgUpper.includes('ROLE') || msgUpper.includes('NOT PERMITTED')) {
      plainEnglishSummary = 'The agent identity profile is not authorized to execute this specific tool or operation.';
      regulatoryStandard = 'SOC 2 CC6.1 (Least Privilege Access Control) & OWASP ASI03 (Identity & Privilege Abuse)';
      riskCategory = 'Unauthorized Privilege Escalation';
      suggestedRemediation = 'Update the agent profile permissions in the Agent Identity Manager or invoke an authorized tool.';
    }

    return {
      ruleId: violation.ruleId,
      packId: violation.packId,
      severity: violation.severity,
      plainEnglishSummary,
      regulatoryStandard,
      riskCategory,
      suggestedRemediation,
    };
  });

  const verdictSummary = `🚫 The tool invocation '${toolCall.tool}' was blocked by Aegis Invariant Kernel. ${explanations.length} security policy violation(s) were identified.`;

  return {
    tool: toolCall.tool,
    allowed: false,
    verdictSummary,
    latencyMs: verdict.latencyMs,
    explanations,
    complianceStatement: 'Enforced under EU AI Act Article 14/15 and NIST AI RMF MANAGE-2.4 fail-closed policy.',
  };
}
