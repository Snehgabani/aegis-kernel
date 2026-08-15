import * as readline from 'node:readline';
import pc from 'picocolors';
import { AegisEngine, type ToolCall } from '@aegis-kernel/core';

export function runRepl(): void {
  const engine = new AegisEngine({ mode: 'enforce' });

  console.log(pc.bold(pc.cyan('\n🛡️  Aegis Invariant Kernel — Interactive Terminal REPL')));
  console.log(pc.gray('Type a tool call as: <tool_name> <json_params>'));
  console.log(pc.dim('Example: execute_sql {"query": "DELETE FROM users WHERE 1=1;"}'));
  console.log(pc.dim('Type "exit" or "quit" to leave.\n'));

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: pc.bold(pc.blue('aegis> ')),
  });

  rl.prompt();

  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (trimmed === 'exit' || trimmed === 'quit') {
      rl.close();
      return;
    }

    if (!trimmed) {
      rl.prompt();
      return;
    }

    const firstSpace = trimmed.indexOf(' ');
    let tool = trimmed;
    let params: any = {};

    if (firstSpace !== -1) {
      tool = trimmed.substring(0, firstSpace);
      const rest = trimmed.substring(firstSpace + 1).trim();
      try {
        params = JSON.parse(rest);
      } catch (err: any) {
        console.log(pc.red(`❌ Invalid JSON parameters: ${err.message}`));
        rl.prompt();
        return;
      }
    }

    const toolCall: ToolCall = { tool, params };
    const t0 = performance.now();
    const verdict = engine.evaluate(toolCall);
    const t1 = performance.now();

    if (verdict.allowed) {
      console.log(pc.green(`\n  ✅ ALLOWED (Cleared all policy invariants in ${(t1 - t0).toFixed(2)}ms)`));
      console.log(pc.gray(`     SHA-256 ProofHash: ${verdict.proofHash}`));
    } else {
      console.log(pc.red(`\n  🛑 BLOCKED (Invariant Violation in ${(t1 - t0).toFixed(2)}ms)`));
      for (const v of verdict.violations) {
        console.log(pc.red(`     • [${v.severity.toUpperCase()}] ${v.ruleId}: ${v.message}`));
        if (v.suggestedFix) {
          console.log(pc.cyan(`       💡 Suggested Fix: ${v.suggestedFix}`));
        }
      }
      console.log(pc.gray(`     SHA-256 ProofHash: ${verdict.proofHash}`));
    }
    console.log('');
    rl.prompt();
  }).on('close', () => {
    console.log(pc.gray('\nExiting Aegis REPL. Goodbye!\n'));
    process.exit(0);
  });
}
