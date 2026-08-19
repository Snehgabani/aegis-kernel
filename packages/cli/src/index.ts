import { Command } from 'commander';
import { runInit } from './init.js';
import { runTests } from './test-runner.js';
import { runReport } from './report.js';
import { runLicenseActivate, runLicenseStatus } from './license-cli.js';
import { runPricing } from './pricing-cli.js';
import { runPackList, runPackValidate, runPackCreate } from './registry-cli.js';
import { runHubList, runHubSearch, runHubInstall } from './hub-cli.js';
import { runRepl } from './repl-cli.js';
import { runBenchmark, runPublicEval } from './benchmark-cli.js';
import { runMatrix } from './matrix-cli.js';
import { runComplianceExport, runExplainToolCall } from './compliance-cli.js';
import { runVerifyProof } from './verify-proof-cli.js';
import { runScan } from './scan-cli.js';
import { runReplay } from './replay-cli.js';
import { runDoctor } from './doctor-cli.js';
import { runAuditReport } from './audit-report-cli.js';

const program = new Command();

program
  .name('aegis')
  .description('Aegis Invariant Kernel: Deterministic Tool-Call Safety Clearance Gateway for AI Agents')
  .version('1.0.1');

program
  .command('scan [path]')
  .description('Recursively scan workspace, prompts, and MCP tool definitions for security vulnerabilities')
  .action((targetPath?: string) => {
    runScan(targetPath || '.');
  });

program
  .command('replay <logPath>')
  .description('Deterministically replay historical audit log events against current policy rules')
  .action((logPath: string) => {
    const result = runReplay(logPath);
    if (!result.ok) process.exitCode = 1;
  });

program
  .command('doctor')
  .description('Run comprehensive diagnostic health checks across all Aegis subsystems')
  .action(async () => {
    await runDoctor();
  });

program
  .command('init')
  .description('Initialize aegis.config.yaml and local .aegis/ workspace directory')
  .action(() => {
    runInit();
  });

program
  .command('test')
  .description('Run synthetic attack vectors to verify security bounds and compute Agent Safety Scorecard')
  .action(() => {
    runTests();
  });

program
  .command('matrix')
  .description('Display threat coverage cross-walk against OWASP GenAI Top 10 (2026) and MITRE ATLAS')
  .action(() => {
    runMatrix();
  });

program
  .command('report')
  .description('Display telemetry, disaster prevention metrics, and rule accuracy from Learning Ledger')
  .action(() => {
    runReport();
  });

program
  .command('repl')
  .description('Launch interactive terminal REPL for live tool call evaluation')
  .action(() => {
    runRepl();
  });

program
  .command('benchmark')
  .description('Run the statistical benchmark harness (workload profiles, percentiles, throughput)')
  .option('-t, --tricky', 'Run the 100-vector adversarial stress testbed (internal curated dataset)')
  .option('--compare', 'Compare against committed baseline (.benchmark/baseline.json) and gate on regressions')
  .option('--save-baseline', 'Persist current results as the new baseline')
  .option('--json <path>', 'Write machine-readable evidence JSON (default .benchmark/evidence.json)')
  .option('--quick', 'Shorter runs for CI smoke checks')
  .action((options) => {
    process.exitCode = runBenchmark(options);
  });

const evalCmd = program
  .command('eval')
  .description('Run standardized academic benchmarks (injecagent, agentdojo, mcptox, all) and double-blind protocols');

evalCmd
  .command('injecagent')
  .description('Run InjecAgent benchmark (ACL 2024 Indirect Prompt Injection & Direct Harm / Data Exfiltration)')
  .option('-d, --dataset <path>', 'Path to dataset file (JSON or JSONL)')
  .option('-o, --output <path>', 'Save cryptographically signed benchmark evidence JSON')
  .action(async (options) => {
    process.exitCode = await runPublicEval({
      benchmark: 'injecagent',
      datasetPath: options.dataset,
      outputPath: options.output,
    });
  });

evalCmd
  .command('agentdojo')
  .description('Run AgentDojo benchmark (NeurIPS 2024 Dynamic Multi-Domain Benchmark across Banking, Workspace, Slack, Travel)')
  .option('-d, --dataset <path>', 'Path to dataset file (JSON or JSONL)')
  .option('-o, --output <path>', 'Save cryptographically signed benchmark evidence JSON')
  .action(async (options) => {
    process.exitCode = await runPublicEval({
      benchmark: 'agentdojo',
      datasetPath: options.dataset,
      outputPath: options.output,
    });
  });

evalCmd
  .command('mcptox')
  .description('Run MCPTox / MCP-Bench tool poisoning and schema rug-pull benchmark')
  .option('-d, --dataset <path>', 'Path to dataset file (JSON or JSONL)')
  .option('-o, --output <path>', 'Save cryptographically signed benchmark evidence JSON')
  .action(async (options) => {
    process.exitCode = await runPublicEval({
      benchmark: 'mcptox',
      datasetPath: options.dataset,
      outputPath: options.output,
    });
  });

evalCmd
  .command('all', { isDefault: true })
  .description('Run all standardized academic benchmarks (InjecAgent, AgentDojo, MCPTox) with aggregate attestation')
  .option('-o, --output <path>', 'Save cryptographically signed benchmark evidence JSON')
  .option('--blinded', 'Execute cryptographic double-blind evaluation with sealed oracle and Merkle trace')
  .option('--adaptive', 'Run dynamic Tree-of-Attacks (TAP) automated red-teaming fuzzer')
  .action(async (options) => {
    process.exitCode = await runPublicEval({
      benchmark: 'all',
      outputPath: options.output,
      blinded: options.blinded,
      adaptive: options.adaptive,
    });
  });

const hubCmd = program.command('hub').description('Discover, search, and install rule packs from the Aegis Hub registry');

hubCmd
  .command('list')
  .description('List certified community and enterprise rule packs on Aegis Hub')
  .action(() => {
    runHubList();
  });

hubCmd
  .command('search <term>')
  .description('Search Aegis Hub registry for rule packs matching a term')
  .action((term: string) => {
    runHubSearch(term);
  });

hubCmd
  .command('install <packId>')
  .description('Download and install a rule pack into local .aegis/packs/')
  .action((packId: string) => {
    runHubInstall(packId);
  });

const packCmd = program.command('pack').description('Manage, inspect, and validate Aegis Invariant Rule Packs');

packCmd
  .command('list')
  .description('List available community and enterprise rule packs')
  .action(() => {
    runPackList();
  });

packCmd
  .command('create <name>')
  .description('Scaffold a new YAML invariant rule pack in .aegis/packs/')
  .action((name: string) => {
    runPackCreate(name);
  });

packCmd
  .command('validate <file>')
  .description('Validate a custom YAML rule pack against Aegis schema specification')
  .action((file: string) => {
    runPackValidate(file);
  });

const licenseCmd = program.command('license').description('Manage Aegis Enterprise license and active compliance entitlements');

licenseCmd
  .command('activate <key>')
  .description('Activate an enterprise or pro license key')
  .action((key: string) => {
    runLicenseActivate(key);
  });

licenseCmd
  .command('status')
  .description('Display active plan, expiration, and unlocked rule packs')
  .action(() => {
    runLicenseStatus();
  });

const complianceCmd = program
  .command('compliance')
  .description('Enterprise GRC compliance dossier generation and regulatory audit reporting');

complianceCmd
  .command('export')
  .description('Generate an audit-ready compliance dossier (SOC 2, ISO 42001, EU AI Act, NIST AI RMF)')
  .option('-f, --format <format>', 'Export format: markdown or json', 'markdown')
  .option('-o, --output <path>', 'Destination output file path')
  .option('-l, --limit <number>', 'Number of historical events to audit', '1000')
  .action((options) => {
    runComplianceExport({
      format: options.format,
      output: options.output,
      limit: parseInt(options.limit, 10),
    });
  });

complianceCmd
  .command('verify <dossierPath>')
  .description('Cryptographically verify SHA-256 Merkle root chains, Ed25519/HMAC signatures, and regulatory control crosswalks')
  .option('-k, --key <key>', 'Public key (Ed25519 PEM) or secret (HMAC) for signature verification')
  .option('--json', 'Output machine-readable JSON verification report')
  .action((dossierPath: string, options) => {
    const result = runVerifyProof(dossierPath, options);
    if (!result.ok) process.exitCode = 1;
  });

program
  .command('verify-proof <dossierPath>')
  .description('Cryptographically verify SHA-256 Merkle root chains, Ed25519/HMAC signatures, and regulatory control crosswalks')
  .option('-k, --key <key>', 'Public key (Ed25519 PEM) or secret (HMAC) for signature verification')
  .option('--json', 'Output machine-readable JSON verification report')
  .action((dossierPath: string, options) => {
    const result = runVerifyProof(dossierPath, options);
    if (!result.ok) process.exitCode = 1;
  });

program
  .command('explain <tool> [payload]')
  .description('Generate transparent plain-English explanation for a tool call under EU AI Act Art. 13')
  .action((tool: string, payload?: string) => {
    runExplainToolCall(tool, payload || '{}');
  });

program
  .command('pricing')
  .description('View commercial tiers, pricing math, and upgrade checkout links')
  .action(() => {
    runPricing();
  });

program
  .command('audit-report [targetPath]')
  .description('Generate instant executive SOC 2 / ISO 42001 AI Risk Assessment & CPA compliance report')
  .option('-f, --format <format>', 'Report format: markdown or html', 'markdown')
  .option('-o, --output <path>', 'Destination output file path')
  .action((targetPath: string | undefined, options: { format?: string; output?: string }) => {
    runAuditReport(targetPath || '.', options);
  });

program.parse(process.argv);
