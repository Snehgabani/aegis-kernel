import * as fs from 'node:fs';
import * as path from 'node:path';
import pc from 'picocolors';

export function runInit(): void {
  const configPath = path.resolve(process.cwd(), 'aegis.config.yaml');

  if (fs.existsSync(configPath)) {
    console.log(pc.yellow(`⚠️  Config file already exists at ${configPath}`));
    return;
  }

  const defaultYaml = `# aegis.config.yaml — Aegis Invariant Kernel Configuration

# Config schema version (validated against .aegis/schemas/aegis-config.schema.json)
version: "1.0"

# Operating mode: "enforce" (hard-block) or "shadow" (log-only audit)
mode: "enforce"

# Fail-safe behavior if engine evaluation encounters an unexpected error
# "fail-closed" = block action + log error (security default, recommended for production)
failPolicy: "fail-closed"

# Pre-configured rule packs
packs:
  - "@aegis/sql-guard"
  - "@aegis/finance-guard"
  - "@aegis/data-guard"

# Structured telemetry & event logging
logging:
  enabled: true
  path: ".aegis/events.jsonl"
  ledgerPath: ".aegis/learning-ledger.json"
  maxFileSizeMb: 50

# Runtime thresholds for alerts
thresholds:
  maxLatencyMs: 10
  maxFalsePositiveRate: 0.05
`;

  fs.writeFileSync(configPath, defaultYaml, 'utf8');

  // Create .aegis directory
  const aegisDir = path.resolve(process.cwd(), '.aegis');
  if (!fs.existsSync(aegisDir)) {
    fs.mkdirSync(aegisDir, { recursive: true });
  }

  console.log(pc.green('✅ Aegis Invariant Kernel initialized successfully!'));
  console.log(pc.cyan(`📄 Created config: ${configPath}`));
  console.log(pc.gray(`📁 Initialized directory: ${aegisDir}`));
  console.log('\nNext steps:');
  console.log('  1. Run ' + pc.bold('npx aegis test') + ' to simulate security checks');
  console.log('  2. Import ' + pc.bold('@aegis-kernel/core') + ' or framework adapters in your agent code\n');
}
