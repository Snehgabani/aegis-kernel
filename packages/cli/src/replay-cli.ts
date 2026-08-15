import fs from 'fs';
import pc from 'picocolors';
import { AegisEngine } from '@aegis-kernel/core';

export interface ReplayResult {
  totalEvents: number;
  blockedCount: number;
  allowedCount: number;
  differences: number;
}

export function runReplay(auditLogPath: string): ReplayResult {
  console.log(pc.bold(pc.cyan('\n⏪ AEGIS DETERMINISTIC AUDIT REPLAY ENGINE')));
  console.log(pc.gray(`Replaying historical events from: ${auditLogPath}...\n`));

  if (!fs.existsSync(auditLogPath)) {
    console.error(pc.red(`Error: Audit log file not found at ${auditLogPath}`));
    return { totalEvents: 0, blockedCount: 0, allowedCount: 0, differences: 0 };
  }

  let events: any[] = [];
  try {
    const raw = fs.readFileSync(auditLogPath, 'utf8');
    if (auditLogPath.endsWith('.jsonl')) {
      events = raw.trim().split('\n').map(l => JSON.parse(l));
    } else {
      events = JSON.parse(raw);
    }
  } catch (e: any) {
    console.error(pc.red(`Failed to parse audit log: ${e.message}`));
    return { totalEvents: 0, blockedCount: 0, allowedCount: 0, differences: 0 };
  }

  const engine = new AegisEngine();
  let blockedCount = 0;
  let allowedCount = 0;
  let differences = 0;

  events.forEach((evt, idx) => {
    const toolCall = {
      tool: evt.toolName || evt.tool,
      params: evt.params || evt.input || {},
    };

    const verdict = engine.evaluate(toolCall);
    const decision = verdict.allowed ? 'ALLOWED' : 'BLOCKED';

    if (decision === 'BLOCKED') {
      blockedCount++;
    } else {
      allowedCount++;
    }

    if (evt.verdict && evt.verdict !== decision) {
      differences++;
      console.log(pc.yellow(`  ⚠️  Event #${idx + 1} (${toolCall.tool}): Past=${evt.verdict} -> Current=${decision}`));
    }
  });

  console.log(pc.bold('\n📊 REPLAY RESULTS:'));
  console.log(`  Total Replayed: ${pc.bold(events.length)}`);
  console.log(`  Allowed:        ${pc.green(allowedCount)}`);
  console.log(`  Blocked:        ${pc.red(blockedCount)}`);
  console.log(`  Policy Drifts:  ${differences > 0 ? pc.yellow(differences) : pc.green('0 (100% Consistent)')}\n`);

  return { totalEvents: events.length, blockedCount, allowedCount, differences };
}
