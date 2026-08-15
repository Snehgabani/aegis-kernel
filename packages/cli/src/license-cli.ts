import { AegisLicenseManager } from '@aegis-kernel/core';
import pc from 'picocolors';

export function runLicenseActivate(key: string): void {
  if (!key || typeof key !== 'string') {
    console.log(pc.red('❌ Error: Please provide a license key to activate.'));
    console.log(`Usage: ${pc.bold('aegis license activate <key>')}`);
    return;
  }

  const manager = new AegisLicenseManager();
  const res = manager.saveLicense(key.trim());

  if (!res.valid || !res.active) {
    console.log(pc.red(`❌ License Activation Failed: ${res.error || 'Invalid signature'}`));
    return;
  }

  console.log(pc.green('\n✅ Aegis Enterprise License Activated Successfully!'));
  console.log(pc.cyan(`  Tier:         ${pc.bold(res.tier.toUpperCase())}`));
  console.log(`  Customer:     ${pc.white(res.payload?.customerId || 'N/A')}`);
  console.log(`  Expires:      ${pc.gray(res.payload?.expiresAt || 'N/A')}`);
  console.log(`  Features:     ${pc.green(res.payload?.features?.join(', ') || 'N/A')}`);
  console.log(pc.gray('\nLicense written to .aegis/license.json (verified offline with zero latency overhead).\n'));
}

export function runLicenseStatus(): void {
  const manager = new AegisLicenseManager();
  const res = manager.resolveActiveLicense();

  console.log(pc.bold(pc.cyan('\n🛡️  Aegis License & Entitlements Status\n')));
  console.log(pc.gray('═'.repeat(60)));
  console.log(`  Active Plan:       ${pc.bold(pc.green(res.tier.toUpperCase()))}`);
  console.log(`  Status:            ${res.active ? pc.green('ACTIVE ✅') : pc.red('EXPIRED 🛑')}`);
  console.log(`  Customer ID:       ${pc.white(res.payload?.customerId || 'community_user')}`);
  console.log(`  Expires At:        ${pc.gray(res.payload?.expiresAt ? new Date(res.payload.expiresAt).toLocaleDateString() : 'Perpetual')}`);
  console.log(`  Monthly Limit:     ${pc.cyan(res.payload?.maxMonthlyChecks === 'unlimited' ? 'Unlimited' : `${res.payload?.maxMonthlyChecks?.toLocaleString()} checks/mo`)}`);
  console.log(pc.gray('═'.repeat(60)));

  console.log(pc.bold('\n📦 Unlocked Rule Packs:'));
  const packs = [
    { id: '@aegis/sql-guard', name: 'SQL Mutation & Destructive Guard', tier: 'Community (Free)' },
    { id: '@aegis/finance-guard', name: 'Financial Bounds & Velocity Guard', tier: 'Community (Free)' },
    { id: '@aegis/data-guard', name: 'PII & Secret Leak Guard', tier: 'Community (Free)' },
    { id: '@aegis/hipaa-guard', name: 'HIPAA Healthcare & PHI Guard', tier: 'Pro / Enterprise' },
    { id: '@aegis/pci-dss-guard', name: 'PCI-DSS Payment Security Guard', tier: 'Pro / Enterprise' },
    { id: '@aegis/soc2-guard', name: 'SOC 2 Infrastructure Integrity Guard', tier: 'Scale / Enterprise' },
  ];

  for (const p of packs) {
    const isEntitled = manager.isPackEntitled(p.id);
    const badge = isEntitled ? pc.green('[UNLOCKED]') : pc.gray('[LOCKED - UPGRADE REQUIRED]');
    console.log(`  • ${pc.bold(p.id.padEnd(24))} ${badge} ${pc.dim(`(${p.tier})`)}`);
  }

  if (res.tier === 'community') {
    console.log(pc.yellow('\n💡 Run `aegis pricing` to upgrade to Pro/Enterprise and unlock compliance packs.\n'));
  } else {
    console.log('\n');
  }
}
