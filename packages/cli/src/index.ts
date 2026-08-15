import { Command } from 'commander';
import { runInit } from './init.js';
import { runTests } from './test-runner.js';
import { runReport } from './report.js';
import { runLicenseActivate, runLicenseStatus } from './license-cli.js';
import { runPricing } from './pricing-cli.js';
import { runPackList, runPackValidate, runPackCreate } from './registry-cli.js';
import { runRepl } from './repl-cli.js';
import { runBenchmark } from './benchmark-cli.js';

const program = new Command();

program
  .name('aegis')
  .description('Aegis Invariant Kernel: Deterministic Tool-Call Safety Clearance Gateway for AI Agents')
  .version('1.0.0');

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
  .description('Run evaluation harness against public prompt-injection & safety benchmarks')
  .option('-t, --tricky', 'Run the 100-vector adversarial stress testbed')
  .action((options) => {
    runBenchmark(options);
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

program
  .command('pricing')
  .description('View commercial tiers, pricing math, and upgrade checkout links')
  .action(() => {
    runPricing();
  });

program.parse(process.argv);



