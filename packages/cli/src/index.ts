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
import { runMcpInventoryScan, printMcpScanResult } from './mcp-inventory.js';
import { runPackSign, runPackVerify } from './pack-sign-cli.js';
import { runRedTeam } from './redteam-cli.js';
import { runReplay } from './replay-cli.js';
import { runDoctor } from './doctor-cli.js';
import { runAuditReport } from './audit-report-cli.js';
import { runTelemetry } from './telemetry-cmd.js';
import { runToolCoverage } from './tools-coverage-cmd.js';
import { runDiagnose } from './diagnose-cmd.js';
import { runSynthesize } from './synthesize-cli.js';
import { runDagTrace } from './dag-trace-cli.js';
import { runPolicyProve, runPolicyVerify } from './commitment-cli.js';

const program = new Command();

program
  .name('aegis')
  .description('Aegis Invariant Kernel: Deterministic Tool-Call Safety Clearance Gateway for AI Agents')
  .version('1.0.1');

program
  .command('policy-prove <policyId> <min> <max> <privateValue>')
  .description('Generate cryptographic hash commitment proving private value is within policy bounds')
  .option('-o, --output <path>', 'Output JSON file path for generated proof artifact')
  .action((policyId: string, min: string, max: string, privateValue: string, opts: { output?: string }) => {
    runPolicyProve(policyId, parseFloat(min), parseFloat(max), parseFloat(privateValue), opts);
  });

program
  .command('policy-verify <proofPath> <min> <max>')
  .description('External auditor verification of a cryptographic policy commitment proof artifact')
  .action((proofPath: string, min: string, max: string) => {
    runPolicyVerify(proofPath, parseFloat(min), parseFloat(max));
  });

program
  .command('synthesize <schemaPath>')
  .description('Synthesize deterministic RulePacks from OpenAPI 3.0/3.1 or MCP JSON schemas')
  .option('-o, --output <path>', 'Output JSON file path for generated RulePack')
  .action((schemaPath: string, opts: { output?: string }) => {
    runSynthesize(schemaPath, opts);
  });

program
  .command('dag-trace <dagPath>')
  .description('Render forensic Mermaid flowchart or ASCII trace of an Execution DAG with FIDES security tags')
  .option('-f, --format <format>', 'Output format: mermaid (default) or ascii', 'mermaid')
  .option('-o, --output <path>', 'Output file path')
  .action((dagPath: string, opts: { format?: 'mermaid' | 'ascii'; output?: string }) => {
    runDagTrace(dagPath, opts);
  });

program
  .command('scan [path]')
  .description('Recursively scan workspace, prompts, and MCP tool definitions for security vulnerabilities')
  .action((targetPath?: string) => {
    runScan(targetPath || '.');
  });

program
  .command('scan-mcp [path]')
  .description('Audit MCP server inventories (mcp.json, .cursor/mcp.json, claude_desktop_config.json): missing auth, insecure transport, unpinned packages, lock-file drift, tool poisoning')
  .option('--lock <lockFile>', 'verify live inventories against an aegis-mcp-lock.json manifest')
  .option('--pin <lockFile>', 'write/refresh an aegis-mcp-lock.json manifest pinning current server configs')
  .action((targetPath: string | undefined, opts: { lock?: string; pin?: string }) => {
    const result = runMcpInventoryScan(targetPath || '.', { lockPath: opts.lock, pinPath: opts.pin });
    printMcpScanResult(result);
    const blocking = result.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
    if (blocking.length > 0) process.exitCode = 1;
  });

program
  .command('red-team [action]')
  .description('Adaptive red-team harness: TAP payload-mutation tree search + MCP tool-poisoning stress')
  .option('--suite <suite>', 'tap | poisoning | trajectory | all (default all)')
  .option('--depth <n>', 'TAP search depth (default 4)', parseInt)
  .option('--branching <n>', 'TAP branching factor (default 4)', parseInt)
  .option('-o, --output <path>', 'Write red-team evidence JSON report')
  .action((action: string | undefined, opts: { suite?: string; depth?: number; branching?: number; output?: string }) => {
    if (action && action !== 'run') {
      console.error(`Unknown red-team action '${action}'. Usage: aegis red-team run`);
      process.exitCode = 1;
      return;
    }
    void runRedTeam({
      suite: (opts.suite as 'tap' | 'poisoning' | 'all') ?? 'all',
      depth: opts.depth,
      branching: opts.branching,
      output: opts.output,
    }).then((code) => {
      if (code !== 0) process.exitCode = code;
    });
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

packCmd
  .command('sign <file>')
  .description('Sign a rule pack with an Ed25519 private key (writes <file>.sig.json sidecar manifest) — AISVS C10.1.1')
  .requiredOption('--key <privateKeyPem>', 'Path to Ed25519 private key (PEM)')
  .option('--signer <name>', 'Signer identity recorded in the manifest')
  .action((file: string, opts: { key: string; signer?: string }) => {
    runPackSign(file, opts.key, opts.signer);
  });

packCmd
  .command('verify <file>')
  .description('Verify a rule pack against its signature manifest + trusted public key(s) (fail-closed, exit 1 on failure)')
  .requiredOption('--key <publicKeyPem>', 'Path to trusted Ed25519 public key (PEM); repeat or comma-separate for multiple')
  .action((file: string, opts: { key: string | string[] }) => {
    const keys = (Array.isArray(opts.key) ? opts.key : [opts.key]).flatMap((k) => k.split(','));
    runPackVerify(file, keys);
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

program
  .command('telemetry [action]')
  .description('Inspect, export, or manage local privacy-preserving telemetry and diagnostic metrics')
  .option('-o, --output <path>', 'Destination output file path for telemetry export')
  .action((action?: string, options?: { output?: string }) => {
    runTelemetry(action || 'status', options);
  });

program
  .command('stats')
  .description('Alias for "aegis telemetry status": display real-time evaluation percentiles and violation distribution')
  .action(() => {
    runTelemetry('status');
  });

program
  .command('tools')
  .description('Audit tool invocation counts, invariant guard coverage, and LLM escape vectors')
  .option('--shadow-only', 'Filter to only show unguarded or shadow tools')
  .option('--json', 'Output report in JSON format')
  .action((options: { shadowOnly?: boolean; json?: boolean }) => {
    runToolCoverage(options);
  });

program
  .command('coverage')
  .description('Alias for "aegis tools": display tool guard coverage and LLM escape risk')
  .action(() => {
    runToolCoverage();
  });

program
  .command('shadow-tools')
  .description('Scan and flag unguarded or undocumented tools called by AI agents')
  .action(() => {
    runToolCoverage({ shadowOnly: true });
  });

program
  .command('diagnose <tool> [payload]')
  .description('Perform micro-stage step-by-step diagnostic execution with root-cause diffs')
  .option('--json', 'Output machine-readable diagnostic trace JSON')
  .action((tool: string, payload?: string, options?: { json?: boolean }) => {
    runDiagnose(tool, payload, options);
  });

program
  .command('debug <tool> [payload]')
  .description('Alias for "aegis diagnose": run micro-stage step-by-step diagnostic execution')
  .option('--json', 'Output machine-readable diagnostic trace JSON')
  .action((tool: string, payload?: string, options?: { json?: boolean }) => {
    runDiagnose(tool, payload, options);
  });

program.parse(process.argv);
