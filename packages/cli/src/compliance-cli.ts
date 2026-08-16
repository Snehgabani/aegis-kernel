/**
 * @file packages/cli/src/compliance-cli.ts
 * @description CLI command handler for `aegis compliance export` and `aegis explain`.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  AegisEngine,
  generateComplianceDossier,
  renderComplianceMarkdown,
  renderComplianceHTML,
  renderCompliancePDF,
  generateHumanExplanation,
} from '@aegis-kernel/core';
import type { AegisEvent } from '@aegis-kernel/core';

export function runComplianceExport(options: {
  output?: string;
  format?: string;
  limit?: number;
  key?: string;
  auditorFirm?: string;
  leadAuditor?: string;
}) {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  🛡️  AEGIS GRC COMPLIANCE DOSSIER EXPORTER');
  console.log('═══════════════════════════════════════════════════════════════\n');

  const engine = new AegisEngine();
  const limit = options.limit || 1000;
  const events: AegisEvent[] = engine.getRecentEvents(limit);

  console.log(`📥 Ingested ${events.length} recent audit events from event ledger.`);

  const dossier = generateComplianceDossier(events, engine.getLoadedPacks(), '0'.repeat(64), {
    includeEvents: true,
    signKey: options.key,
    auditorFirm: options.auditorFirm,
    leadAuditor: options.leadAuditor,
  });

  const format = options.format?.toLowerCase() || 'markdown';

  let outputContent: string | Buffer = '';
  let defaultFile = '';

  if (format === 'json') {
    outputContent = JSON.stringify(dossier, null, 2);
    defaultFile = `aegis-compliance-dossier-${Date.now()}.json`;
  } else if (format === 'html') {
    outputContent = renderComplianceHTML(dossier);
    defaultFile = `aegis-compliance-dossier-${Date.now()}.html`;
  } else if (format === 'pdf') {
    outputContent = renderCompliancePDF(dossier);
    defaultFile = `aegis-compliance-dossier-${Date.now()}.pdf`;
  } else {
    outputContent = renderComplianceMarkdown(dossier);
    defaultFile = `aegis-compliance-dossier-${Date.now()}.md`;
  }

  const outputPath = options.output || path.join(process.cwd(), defaultFile);
  fs.writeFileSync(outputPath, outputContent);

  console.log(`\n✅ Compliance dossier generated successfully!`);
  console.log(`📄 Saved to: ${outputPath} (${format.toUpperCase()})`);
  console.log(`🔐 Merkle Root Hash: ${dossier.merkleRootHash}`);
  if (dossier.merkleRootSignature) {
    console.log(`✍️  Cryptographic Signature: ${dossier.merkleRootSignature.slice(0, 32)}... (${dossier.signatureType})`);
  }
  console.log(`📋 Mapped Standards: SOC 2 Type II, ISO/IEC 42001:2023, HIPAA §164.312, NIST AI RMF 1.0, EU AI Act\n`);
  return { ok: true, outputPath, dossier };
}

export function runExplainToolCall(toolName: string, queryOrParams: string) {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  💡  AEGIS EU AI ACT ART. 13 & NIST EXPLAINABILITY ENGINE');
  console.log('═══════════════════════════════════════════════════════════════\n');

  let params: Record<string, any> = {};
  try {
    params = JSON.parse(queryOrParams);
  } catch {
    params = { query: queryOrParams, text: queryOrParams };
  }

  const toolCall = { tool: toolName, params };
  const engine = new AegisEngine();
  const verdict = engine.evaluate(toolCall);
  const explanation = generateHumanExplanation(toolCall, verdict);

  console.log(`Tool:     ${explanation.tool}`);
  console.log(`Verdict:  ${explanation.allowed ? '✅ ALLOWED' : '🚫 BLOCKED'}`);
  console.log(`Latency:  ${explanation.latencyMs}ms\n`);
  console.log(`Summary:  ${explanation.verdictSummary}\n`);

  if (explanation.explanations.length > 0) {
    console.log('📋 Policy Violations & Legal Standards:');
    explanation.explanations.forEach((exp, idx) => {
      console.log(`\n  [${idx + 1}] Rule: ${exp.ruleId} (${exp.severity.toUpperCase()})`);
      console.log(`      Summary:     ${exp.plainEnglishSummary}`);
      console.log(`      Risk Level:  ${exp.riskCategory}`);
      console.log(`      Standard:    ${exp.regulatoryStandard}`);
      console.log(`      Remediation: ${exp.suggestedRemediation}`);
    });
  }

  console.log(`\n📜 ${explanation.complianceStatement}\n`);
}
