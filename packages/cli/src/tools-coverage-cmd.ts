import pc from 'picocolors';
import { ToolUsageTracker } from '@aegis-kernel/diagnostics';

export function runToolCoverage(options: { shadowOnly?: boolean; json?: boolean } = {}): void {
  const tracker = new ToolUsageTracker([
    'database_exec',
    'finance_payout',
    'workspace_fetch',
    'email_sender',
    'system_shell',
    'slack_notify',
  ]);

  // Seed with standard Aegis rules
  tracker.attachRule('database_exec', '@aegis/sql-guard:SQL-01');
  tracker.attachRule('database_exec', '@aegis/sql-guard:SQL-02');
  tracker.attachRule('finance_payout', '@aegis/finance-guard:FIN-01');
  tracker.attachRule('workspace_fetch', '@aegis/data-guard:DATA-01');

  // Seed sample invocations
  tracker.recordInvocation('database_exec', true);
  tracker.recordInvocation('database_exec', true);
  tracker.recordInvocation('database_exec', false);
  tracker.recordInvocation('finance_payout', true);
  tracker.recordInvocation('finance_payout', false);
  tracker.recordInvocation('workspace_fetch', true);
  tracker.recordInvocation('slack_notify', true); // Unguarded tool call!

  const report = tracker.generateCoverageReport();

  if (options.json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  const boxWidth = 67;
  const line = '═'.repeat(boxWidth);

  console.log(pc.cyan(line));
  console.log(pc.bold(pc.cyan('      🛡️  AEGIS TOOL INVARIANT USAGE & LLM ESCAPE SCORECARD       ')));
  console.log(pc.cyan(line));
  console.log(`  Catalog Declared Tools:   ${pc.bold(report.totalDeclaredTools.toString())}`);
  console.log(`  Tools Invoked by Agent:   ${pc.bold(report.totalInvokedTools.toString())}`);
  console.log(`  Guarded Tools:            ${pc.green(report.guardedToolsCount.toString())}`);
  console.log(`  Unguarded Tools (Risk):   ${report.unguardedToolsCount === 0 ? pc.green('0') : pc.yellow(report.unguardedToolsCount.toString())}`);
  console.log(`  Guard Coverage:           ${report.coveragePercentage >= 80 ? pc.green(`${report.coveragePercentage}%`) : pc.yellow(`${report.coveragePercentage}%`)}`);
  console.log(`  LLM Escape Threat Level:  ${report.llmEscapeRiskLevel === 'LOW' ? pc.green(report.llmEscapeRiskLevel) : pc.red(pc.bold(report.llmEscapeRiskLevel))}`);
  console.log(pc.cyan(line));

  console.log('');
  console.log(pc.bold('  📊 Active Tool Invocations:'));
  for (const tool of report.activeTools) {
    const status = tool.isGuarded
      ? pc.green(`[GUARDED: ${tool.activeInvariantRules.length} rules]`)
      : pc.yellow('[UNGUARDED: ⚠️ ESCAPE RISK]');
    console.log(`    • ${pc.bold(tool.toolName.padEnd(20))} ${status} — Total: ${tool.totalInvocations} (Allowed: ${pc.green(tool.allowedCount.toString())}, Blocked: ${pc.red(tool.blockedCount.toString())})`);
  }

  if (report.shadowTools.length > 0) {
    console.log('');
    console.log(pc.bold(pc.yellow('  ⚠️  Shadow / Unguarded Tool Warnings (LLM Escape Vectors):')));
    for (const tool of report.shadowTools) {
      console.log(`    • ${pc.yellow(tool.toolName)}: Exercised by LLM without active invariant rules!`);
    }
  }

  if (report.unusedTools.length > 0) {
    console.log('');
    console.log(pc.dim('  💤 Unused / Dormant Declared Tools:'));
    for (const tool of report.unusedTools) {
      console.log(pc.dim(`    • ${tool} (0 calls recorded — consider pruning)`));
    }
  }

  console.log('');
  console.log(pc.dim('  Tip: Use "aegis pack create <name>" to attach invariant rules to unguarded tools.'));
  console.log('');
}
