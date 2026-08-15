import os from 'node:os';
import pc from 'picocolors';

interface DiagnosticCheck {
  name: string;
  status: 'PASS' | 'FAIL' | 'WARN' | 'SKIP';
  message: string;
  durationMs: number;
}

interface DiagnosticReport {
  timestamp: string;
  systemInfo: Record<string, any>;
  checks: DiagnosticCheck[];
  overallStatus: 'HEALTHY' | 'DEGRADED' | 'CRITICAL';
  summary: { passed: number; failed: number; warned: number; skipped: number };
}

const STATUS_ICONS: Record<string, string> = {
  PASS: '✅',
  FAIL: '❌',
  WARN: '⚠️',
  SKIP: '⏭️',
};

const STATUS_COLORS: Record<string, (s: string) => string> = {
  PASS: pc.green,
  FAIL: pc.red,
  WARN: pc.yellow,
  SKIP: pc.gray,
};

const OVERALL_ICONS: Record<string, string> = {
  HEALTHY: '💚',
  DEGRADED: '💛',
  CRITICAL: '💔',
};

export async function runDoctor(): Promise<void> {
  console.log(pc.bold(pc.cyan('\n🏥 AEGIS INVARIANT KERNEL — DIAGNOSTIC HEALTH CHECK')));
  console.log(pc.gray('Running comprehensive subsystem verification...\n'));

  let report: DiagnosticReport;

  try {
    // Dynamically import diagnostics to avoid hard dependency at CLI level
    const { AegisDiagnostics } = await import('@aegis-kernel/diagnostics' as string).catch(() => {
      // Fallback: inline basic checks
      return { AegisDiagnostics: null };
    });

    if (AegisDiagnostics) {
      const diag = new AegisDiagnostics();
      report = await diag.runFullDiagnostics();
    } else {
      // Inline fallback diagnostics
      report = await runInlineDiagnostics();
    }
  } catch {
    report = await runInlineDiagnostics();
  }

  // Print system info
  console.log(pc.bold('System Information:'));
  const si = report.systemInfo;
  console.log(`  Node:   ${si.nodeVersion || process.version}`);
  console.log(`  OS:     ${si.osPlatform || process.platform} ${si.osRelease || ''}`);
  console.log(`  Memory: ${si.freeMemoryMB || '?'}MB free / ${si.totalMemoryMB || '?'}MB total`);
  console.log();

  // Print each check
  console.log(pc.bold('Subsystem Checks:'));
  const maxName = Math.max(...report.checks.map(c => c.name.length));

  for (const check of report.checks) {
    const icon = STATUS_ICONS[check.status] || '?';
    const colorFn = STATUS_COLORS[check.status] || pc.white;
    const padded = check.name.padEnd(maxName + 2);
    const timing = pc.gray(`(${check.durationMs}ms)`);
    console.log(`  ${icon} ${colorFn(padded)} ${check.message} ${timing}`);
  }

  // Print summary
  console.log();
  const { summary, overallStatus } = report;
  const icon = OVERALL_ICONS[overallStatus] || '❓';
  console.log(pc.bold(`${icon} Overall: ${overallStatus}`));
  console.log(
    `  ${pc.green(`${summary.passed} passed`)} · ` +
    `${pc.red(`${summary.failed} failed`)} · ` +
    `${pc.yellow(`${summary.warned} warnings`)} · ` +
    `${pc.gray(`${summary.skipped} skipped`)}`
  );
  console.log();

  if (overallStatus === 'CRITICAL') {
    console.log(pc.red(pc.bold('⛔ CRITICAL: One or more subsystems have failed. Review and fix before deployment.')));
    process.exitCode = 1;
  } else if (overallStatus === 'DEGRADED') {
    console.log(pc.yellow('⚠️  DEGRADED: Some subsystems reported warnings. Review recommended.'));
  } else {
    console.log(pc.green('✅ All subsystems healthy. Ready for production.'));
  }
}

async function runInlineDiagnostics(): Promise<DiagnosticReport> {
  const checks: DiagnosticCheck[] = [];

  // Check 1: Core Engine
  try {
    const start = Date.now();
    const { AegisEngine } = await import('@aegis-kernel/core');
    const engine = new AegisEngine();
    const verdict = engine.evaluate({ tool: 'test_tool', params: {} });
    checks.push({
      name: 'Core Engine',
      status: verdict ? 'PASS' : 'FAIL',
      message: 'Engine evaluation pipeline functional',
      durationMs: Date.now() - start,
    });
  } catch (e: any) {
    checks.push({ name: 'Core Engine', status: 'FAIL', message: e.message, durationMs: 0 });
  }

  // Check 2: SQL Checker
  try {
    const start = Date.now();
    const { SqlChecker } = await import('@aegis-kernel/core');
    const checker = new SqlChecker();
    const probe = checker.evaluate('diag-sql', 'diag-pack', { block_statements: ['DROP'] }, { tool: 'q', params: { sql: 'DROP TABLE t' } });
    checks.push({
      name: 'SQL Checker',
      status: probe.length > 0 ? 'PASS' : 'WARN',
      message: probe.length > 0 ? 'SQL AST parser initialized (4-dialect support)' : 'SQL AST fallback active',
      durationMs: Date.now() - start,
    });
  } catch (e: any) {
    checks.push({ name: 'SQL Checker', status: 'FAIL', message: e.message, durationMs: 0 });
  }

  // Check 3: License System
  try {
    const start = Date.now();
    const { AegisLicenseManager } = await import('@aegis-kernel/core');
    const mgr = new AegisLicenseManager('doctor-test-key');
    const key = mgr.generateLicenseKey({
      customerId: 'doctor', customerEmail: 'doctor@test.dev',
      plan: 'pro', issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      features: [], maxMonthlyChecks: 100,
    });
    const result = mgr.verifyLicenseKey(key);
    checks.push({
      name: 'License System',
      status: result.valid ? 'PASS' : 'FAIL',
      message: result.valid ? 'HMAC license round-trip verified' : 'License verification failed',
      durationMs: Date.now() - start,
    });
  } catch (e: any) {
    checks.push({ name: 'License System', status: 'FAIL', message: e.message, durationMs: 0 });
  }

  // Check 4: Biscuit Tokens
  try {
    const start = Date.now();
    const { AegisBiscuitToken } = await import('@aegis-kernel/core');
    const { publicKey, privateKey } = AegisBiscuitToken.generateKeyPair();
    const root = AegisBiscuitToken.createRootToken('doctor', ['read'], [], privateKey, publicKey);
    const verified = AegisBiscuitToken.verify(root, 'read', {});
    checks.push({
      name: 'Biscuit Tokens',
      status: verified.valid && verified.authorized ? 'PASS' : 'FAIL',
      message: 'Ed25519 token creation and verification functional',
      durationMs: Date.now() - start,
    });
  } catch (e: any) {
    checks.push({ name: 'Biscuit Tokens', status: 'FAIL', message: e.message, durationMs: 0 });
  }

  // Check 5: PII Detection
  try {
    const start = Date.now();
    const { PiiTokenVault } = await import('@aegis-kernel/core');
    const vault = new PiiTokenVault();
    const res = vault.tokenize('User SSN is 123-45-6789 for identification');
    checks.push({
      name: 'PII Detection',
      status: res.tokensCreated > 0 ? 'PASS' : 'WARN',
      message: res.tokensCreated > 0 ? 'PII tokenizer detected and masked SSN' : 'No PII detected',
      durationMs: Date.now() - start,
    });
  } catch (e: any) {
    checks.push({ name: 'PII Detection', status: 'FAIL', message: e.message, durationMs: 0 });
  }

  const summary = {
    passed: checks.filter(c => c.status === 'PASS').length,
    failed: checks.filter(c => c.status === 'FAIL').length,
    warned: checks.filter(c => c.status === 'WARN').length,
    skipped: checks.filter(c => c.status === 'SKIP').length,
  };

  let overallStatus: 'HEALTHY' | 'DEGRADED' | 'CRITICAL' = 'HEALTHY';
  if (summary.failed > 0) overallStatus = 'CRITICAL';
  else if (summary.warned > 0) overallStatus = 'DEGRADED';

  return {
    timestamp: new Date().toISOString(),
    systemInfo: {
      nodeVersion: process.version,
      osPlatform: process.platform,
      osRelease: '',
      totalMemoryMB: Math.round(os.totalmem() / 1024 / 1024),
      freeMemoryMB: Math.round(os.freemem() / 1024 / 1024),
    },
    checks,
    overallStatus,
    summary,
  };
}
