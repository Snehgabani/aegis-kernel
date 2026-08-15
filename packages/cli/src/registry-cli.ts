import * as fs from 'node:fs';
import * as path from 'node:path';
import pc from 'picocolors';
import yaml from 'js-yaml';
import { RulePackLoader, AegisLicenseManager } from '@aegis-kernel/core';

export function runPackList(): void {
  const manager = new AegisLicenseManager();
  const license = manager.resolveActiveLicense();

  console.log(pc.bold(pc.cyan('\n📦  Aegis Rule Pack Registry\n')));
  console.log(pc.gray('═'.repeat(70)));

  const allPacks = [
    { id: '@aegis/sql-guard', tier: 'Community (Free)', desc: 'SQL AST mutations, DDL block, tautology defense' },
    { id: '@aegis/finance-guard', tier: 'Community (Free)', desc: 'Financial ceilings, transaction velocity limits' },
    { id: '@aegis/data-guard', tier: 'Community (Free)', desc: 'SSN, Credit Cards, API Keys & Secret scanning' },
    { id: '@aegis/hipaa-guard', tier: 'Pro / Enterprise', desc: 'HIPAA ePHI, NPI, DEA registration numbers' },
    { id: '@aegis/pci-dss-guard', tier: 'Pro / Enterprise', desc: 'PCI-DSS v4.0 PAN tokenization, CVV exclusion' },
    { id: '@aegis/soc2-guard', tier: 'Scale / Enterprise', desc: 'SOC 2 Type II path traversal, privileged mutations' },
    { id: '@aegis/fintech-trade-guard', tier: 'Enterprise', desc: 'Algorithmic trading ceilings, slippage boundaries' },
    { id: '@aegis/legal-privilege-guard', tier: 'Enterprise', desc: 'Attorney-client privilege & seal protection' },
  ];

  for (const p of allPacks) {
    const isEntitled = manager.isPackEntitled(p.id);
    const badge = isEntitled ? pc.green('[UNLOCKED]') : pc.gray('[LOCKED]');
    console.log(`  • ${pc.bold(p.id.padEnd(30))} ${badge} ${pc.cyan(p.tier.padEnd(20))}`);
    console.log(`    ${pc.dim(p.desc)}`);
  }

  console.log('\n' + pc.gray('═'.repeat(70)));
  console.log(pc.dim(`  Active License: ${pc.bold(license.tier.toUpperCase())} (${license.active ? 'ACTIVE' : 'INACTIVE'})`));
  console.log(pc.dim('  Run `aegis pack create <name>` to scaffold a new proprietary rule pack.'));
  console.log(pc.dim('  Run `aegis pack validate <file.yaml>` to verify custom packs.\n'));
}

export function runPackCreate(name: string): void {
  if (!name) {
    console.log(pc.red('❌ Error: Pack name is required. Example: npx aegis pack create custom-sec-guard'));
    return;
  }

  const cleanName = name.toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const fileName = cleanName.endsWith('.yaml') || cleanName.endsWith('.yml') ? cleanName : `${cleanName}.yaml`;
  const targetDir = path.resolve(process.cwd(), '.aegis/packs');
  const targetPath = path.join(targetDir, fileName);

  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  if (fs.existsSync(targetPath)) {
    console.log(pc.yellow(`⚠️  Rule pack already exists at ${targetPath}`));
    return;
  }

  const packTemplate = `id: custom/${cleanName}
name: ${name.charAt(0).toUpperCase() + name.slice(1)} Invariant Security Guard
version: 1.0.0
description: Proprietary enterprise invariant rule pack for ${cleanName}
rules:
  - id: ${cleanName.toUpperCase()}-001
    name: Prohibit Unauthorized High-Risk Actions
    description: Enforces parameter constraints and blocks unsafe tool executions
    severity: critical
    condition:
      type: numeric
      params:
        target_field: params.amount
        operator: "<="
        max: 5000
    suggested_fix: "Ensure amount is less than or equal to 5000."

  - id: ${cleanName.toUpperCase()}-002
    name: Restrict Production Tenant Scope
    description: Verifies session tenant matches destination parameters
    severity: critical
    condition:
      type: state
      params:
        assertion: "state.tenantId == params.tenantId"
        tenant_field: "tenantId"
    suggested_fix: "Restrict tool calls strictly to authenticated tenant context."
`;

  fs.writeFileSync(targetPath, packTemplate, 'utf8');
  console.log(pc.green(`\n✅ Created new rule pack at: ${pc.bold(targetPath)}`));
  console.log(pc.dim(`\nNext steps:`));
  console.log(`  1. Edit rule definitions in ${targetPath}`);
  console.log(`  2. Validate pack syntax: ${pc.cyan(`npx aegis pack validate ${targetPath}`)}`);
  console.log(`  3. Test with live engine: ${pc.cyan('npx aegis test')}\n`);
}

export function runPackValidate(filePath: string): void {
  if (!filePath || !fs.existsSync(filePath)) {
    console.log(pc.red(`❌ Error: File not found at '${filePath}'`));
    return;
  }

  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const parsed = yaml.load(content);
    const isValid = RulePackLoader.validatePack(parsed);

    if (isValid) {
      const pack = parsed as any;
      console.log(pc.green(`\n✅ Rule Pack '${pack.name}' (v${pack.version}) is VALID!`));
      console.log(`  ID:          ${pc.cyan(pack.id)}`);
      console.log(`  Rules Count: ${pc.bold(pack.rules?.length || 0)}`);
      for (const r of pack.rules || []) {
        console.log(`    - [${r.severity.toUpperCase()}] ${r.id}: ${r.description}`);
      }
      console.log('\n');
    } else {
      console.log(pc.red(`\n❌ Validation Failed: Rule pack does not conform to Aegis schema specification.\n`));
    }
  } catch (err: any) {
    console.log(pc.red(`\n❌ Error parsing YAML: ${err.message}\n`));
  }
}
