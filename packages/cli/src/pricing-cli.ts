import pc from 'picocolors';

export function runPricing(): void {
  console.log(pc.bold(pc.cyan('\n💎  Aegis Invariant Kernel: Plans & Monetization Tiers\n')));
  console.log(pc.gray('═'.repeat(70)));

  const tiers = [
    {
      name: 'COMMUNITY',
      price: '$0 / forever',
      badge: pc.green('FREE & OPEN SOURCE'),
      target: 'Individual developers & prototype agents',
      features: [
        'Local deterministic Invariant Engine (<2ms)',
        '3 Base Rule Packs (@aegis/sql-guard, finance-guard, data-guard)',
        'Zero-Eval AST Custom Expression DSL',
        'Local .aegis/events.jsonl & learning-ledger.json',
        'Framework adapters (MCP, LangChain, OpenAI, Anthropic)',
        'Up to 10,000 local checks/month',
      ],
    },
    {
      name: 'PRO',
      price: '$49 / month',
      badge: pc.cyan('MOST POPULAR'),
      target: 'Production agent developers & startups',
      features: [
        'Everything in Community tier',
        'HIPAA Healthcare & PHI Guard (@aegis/hipaa-guard)',
        'PCI-DSS v4.0 Card Data Invariant Guard (@aegis/pci-dss-guard)',
        'Offline signed license key (zero-latency validation)',
        'Cloud telemetry receiver & aggregated audit trail export',
        'Up to 100,000 checks/month',
        'Direct email engineering support',
      ],
    },
    {
      name: 'SCALE',
      price: '$199 / month',
      badge: pc.yellow('FOR GROWING TEAMS'),
      target: 'Fintech & high-throughput agent workflows',
      features: [
        'Everything in Pro tier',
        'SOC 2 Type II System Invariants (@aegis/soc2-guard)',
        'Centralized team dashboard & triage management',
        'Slack & PagerDuty webhook alert dispatch',
        'Up to 1,000,000 checks/month',
        'Priority feature requests',
      ],
    },
    {
      name: 'ENTERPRISE',
      price: '$499 / month (or custom contract)',
      badge: pc.magenta('ENTERPRISE GRADE'),
      target: 'Regulated enterprises, banks, & healthcare systems',
      features: [
        'Everything in Scale tier',
        'Unlimited throughput & custom high-volume SLA',
        'Custom proprietary Rule Pack development & validation',
        'Air-gapped on-premise verification & dedicated license server',
        'Security compliance attestation package (SOC 2, HIPAA, ISO 42001)',
        'Dedicated Slack support channel & 1-hour critical SLA',
      ],
    },
  ];

  for (const t of tiers) {
    console.log(`\n${pc.bold(pc.white(t.name.padEnd(14)))} ${pc.bold(t.price.padEnd(16))} ${t.badge}`);
    console.log(pc.dim(`Target: ${t.target}`));
    for (const f of t.features) {
      console.log(`  ${pc.green('✓')} ${f}`);
    }
  }

  console.log('\n' + pc.gray('═'.repeat(70)));
  console.log(pc.bold('\n🚀 Get Started & Upgrade:'));
  console.log(`  • Self-Serve Pro ($49/mo):     ${pc.cyan('https://buy.stripe.com/aegis_pro_checkout')}`);
  console.log(`  • Scale ($199/mo):             ${pc.cyan('https://buy.stripe.com/aegis_scale_checkout')}`);
  console.log(`  • Enterprise Contract:         ${pc.cyan('mailto:enterprise@aegis-kernel.dev')}`);
  console.log(`  • Activate License:            ${pc.bold('npx aegis license activate <your-key>')}\n`);
}
