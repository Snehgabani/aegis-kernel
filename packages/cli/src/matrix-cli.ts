/**
 * Aegis CLI — OWASP 2026 & MITRE ATLAS Threat Matrix Cross-Walk Inspector
 */

import pc from 'picocolors';

export function runMatrix(): void {
  console.log(pc.bold(pc.cyan('\n🛡️  Aegis Threat Matrix — OWASP GenAI Top 10 (2026) & MITRE ATLAS Cross-Walk\n')));
  console.log(pc.gray('═'.repeat(80)));

  const matrix = [
    {
      owasp: 'LLM01: Prompt Injection',
      atlas: 'AML.T0051 / AML.T0054',
      pack: '@aegis/sql-guard',
      status: pc.green('ENFORCED (AST-001)'),
      desc: 'AST statement whitelist, block-comment evasion defense, tautology stripping',
    },
    {
      owasp: 'LLM02: Data Disclosure',
      atlas: 'AML.T0048 / AML.T0053',
      pack: '@aegis/data-guard',
      status: pc.green('ENFORCED (PII-001)'),
      desc: 'Zero-width unicode normalization, API token & Secret tokenization',
    },
    {
      owasp: 'LLM06: Excessive Agency',
      atlas: 'AML.T0056 (Tool Abuse)',
      pack: '@aegis/finance-guard',
      status: pc.green('ENFORCED (FIN-001)'),
      desc: 'Mathematical ceiling verification, velocity bounds, scientific notation clamp',
    },
    {
      owasp: 'LLM07: Cross-Tenant Leaks',
      atlas: 'AML.T0057 (Tenant Spoof)',
      pack: '@aegis/soc2-guard',
      status: pc.green('ENFORCED (SOC2-004)'),
      desc: 'Cryptographic session-tenant binding, strict partition state lock',
    },
    {
      owasp: 'LLM08: State Tampering',
      atlas: 'AML.T0058 (Memory Poison)',
      pack: '@aegis-kernel/core',
      status: pc.green('ENFORCED (LEDGER-001)'),
      desc: 'SHA-256 proof commitments, immutable tamper-evident event log',
    },
  ];

  for (const item of matrix) {
    console.log(`  • ${pc.bold(item.owasp.padEnd(28))} ${pc.yellow(item.atlas.padEnd(25))} ${item.status}`);
    console.log(`    Pack: ${pc.cyan(item.pack)}`);
    console.log(`    ${pc.dim(item.desc)}\n`);
  }

  console.log(pc.gray('═'.repeat(80)));
  console.log(pc.dim('  Full documentation: docs/OWASP_MITRE_ATLAS_CROSSWALK.md'));
  console.log(pc.dim('  Run `npx aegis test` to execute synthetic verification tests against all threat vectors.\n'));
}
