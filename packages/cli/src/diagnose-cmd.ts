import pc from 'picocolors';
import { AegisEngine } from '@aegis-kernel/core';
import { RemediationDiffGenerator } from '@aegis-kernel/diagnostics';

export function runDiagnose(toolName: string, payloadStr?: string, options: { json?: boolean } = {}): void {
  let params: Record<string, unknown> = {};

  if (payloadStr) {
    try {
      params = JSON.parse(payloadStr);
    } catch {
      // Treat as raw string query if not valid JSON
      params = { query: payloadStr };
    }
  } else {
    // Default demo payload
    params = { query: 'DELETE FROM users' };
  }

  const engine = new AegisEngine({
    mode: 'enforce',
    failPolicy: 'fail-closed',
    packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard'],
  });

  const verdict = engine.evaluate(
    {
      tool: toolName,
      params,
    },
    { enableDiagnostics: true }
  );

  if (options.json) {
    console.log(JSON.stringify(verdict, null, 2));
    return;
  }

  const boxWidth = 67;
  const line = '═'.repeat(boxWidth);

  console.log(pc.cyan(line));
  console.log(pc.bold(pc.cyan('      🔬  AEGIS STEP-BY-STEP MICRO-STAGE DIAGNOSTIC FORENSIC       ')));
  console.log(pc.cyan(line));
  console.log(`  Target Tool:          ${pc.bold(toolName)}`);
  console.log(`  Payload:              ${pc.dim(JSON.stringify(params).slice(0, 70))}`);
  console.log(`  Verdict:              ${verdict.allowed ? pc.green(pc.bold('✅ ALLOWED')) : pc.red(pc.bold('🛑 BLOCKED'))}`);
  console.log(`  Total Evaluation:     ${pc.bold(`${verdict.latencyMs}ms`)} (hot-path in-process)`);
  console.log(`  Merkle Proof Hash:    ${pc.dim(verdict.proofHash.slice(0, 32))}...`);
  console.log(pc.cyan(line));

  if (verdict.diagnosticTrace) {
    console.log('');
    console.log(pc.bold('  ⏱️  Micro-Stage Execution Waterfall:'));
    for (const stage of verdict.diagnosticTrace.stages) {
      const statusIcon = stage.status === 'PASSED' ? pc.green('✔') : pc.red('✖');
      const stageName = stage.stageName.padEnd(24);
      const duration = `${stage.durationUs} µs`.padStart(10);
      console.log(`    ${statusIcon} ${pc.cyan(stageName)} ${pc.dim(duration)}`);
    }

    if (verdict.diagnosticTrace.rootCauseAnalysis) {
      const rca = verdict.diagnosticTrace.rootCauseAnalysis;
      console.log('');
      console.log(pc.bold(pc.red('  🚨 Deterministic Root-Cause Forensic Diagnosis:')));
      console.log(`    • Failure Category:   ${pc.bold(pc.yellow(rca.failureCategory))}`);
      console.log(`    • Culprit Rule ID:    ${pc.bold(pc.red(rca.primaryCulpritRule || 'UNKNOWN'))}`);
      console.log(`    • Remediation Action: ${pc.bold(pc.green(rca.remediationAction))}`);

      // Synthesize unified remediation diff
      let diffOutput = rca.suggestedFixDiff;
      if (!diffOutput && typeof params.query === 'string') {
        const generated = RemediationDiffGenerator.generateSqlDiff(params.query, rca.primaryCulpritRule || 'SQL-01');
        diffOutput = generated.diff;
      }

      if (diffOutput) {
        console.log('');
        console.log(pc.bold('  🛠️  Unified Remediation Diff (Patch Suggestion):'));
        const diffLines = diffOutput.split('\n');
        for (const dl of diffLines) {
          if (dl.startsWith('+')) console.log(`    ${pc.green(dl)}`);
          else if (dl.startsWith('-')) console.log(`    ${pc.red(dl)}`);
          else console.log(`    ${pc.dim(dl)}`);
        }
      }
    }
  }

  console.log('');
  console.log(pc.cyan(line));
  console.log(pc.dim('  Run with --json for raw machine-readable AST diagnostic payloads.'));
  console.log('');
}
