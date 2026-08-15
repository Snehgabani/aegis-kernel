import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runInit } from '../src/init.js';
import { runTests } from '../src/test-runner.js';
import { runReport } from '../src/report.js';
import { runLicenseActivate, runLicenseStatus } from '../src/license-cli.js';
import { runPricing } from '../src/pricing-cli.js';
import { runPackList, runPackValidate } from '../src/registry-cli.js';
import { AegisLicenseManager } from '@aegis-kernel/core';


describe('Aegis CLI Package', () => {
  let tempDir: string;
  let originalCwd: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-cli-test-'));
    originalCwd = process.cwd();
    process.chdir(tempDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe('aegis init command', () => {
    it('should initialize aegis.config.yaml and .aegis/ directory in current workspace', () => {
      runInit();

      const configPath = path.join(tempDir, 'aegis.config.yaml');
      const aegisDir = path.join(tempDir, '.aegis');

      expect(fs.existsSync(configPath)).toBe(true);
      expect(fs.existsSync(aegisDir)).toBe(true);

      const configContent = fs.readFileSync(configPath, 'utf8');
      expect(configContent).toContain('mode: "enforce"');
      expect(configContent).toContain('@aegis/sql-guard');
      expect(configContent).toContain('@aegis/finance-guard');
      expect(configContent).toContain('@aegis/data-guard');
    });

    it('should not overwrite existing aegis.config.yaml if already present', () => {
      const configPath = path.join(tempDir, 'aegis.config.yaml');
      fs.writeFileSync(configPath, '# custom existing config', 'utf8');

      runInit();

      const content = fs.readFileSync(configPath, 'utf8');
      expect(content).toBe('# custom existing config');
    });
  });

  describe('aegis test command', () => {
    it('should execute synthetic testbed without process failure on clean vectors', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      
      expect(() => runTests()).not.toThrow();
      
      const loggedText = consoleSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(loggedText).toContain('AEGIS AGENT SAFETY SCORECARD');
      expect(loggedText).toContain('Total Test Vectors:   12');
      expect(loggedText).toContain('Passed Checks:');
      expect(loggedText).toContain('Safety Score:');
      
      consoleSpy.mockRestore();
    });
  });

  describe('aegis report command', () => {
    it('should display triage report with empty ledger message when no events exist', async () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      const customLedgerPath = path.join(tempDir, 'empty-ledger.json');

      await runReport({ ledgerPath: customLedgerPath });

      const loggedText = consoleSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(loggedText).toContain('Aegis Policy & Invariant Clearance: Telemetry & Triage Report');
      expect(loggedText).toContain('No rules triggered yet');

      consoleSpy.mockRestore();
    });

    it('should display active rule performance and triage status from seeded ledger', async () => {
      const customLedgerPath = path.join(tempDir, 'seeded-ledger.json');
      const sampleLedger = {
        totalEventsProcessed: 100,
        totalBlocked: 10,
        totalAllowed: 90,
        totalOverrides: 1,
        rulePerformance: {
          'SQL-001': {
            timesEvaluated: 50,
            timesFired: 8,
            overridesCount: 0,
            overrideRatio: 0.0,
            averageLatencyMs: 1.25,
            triageStatus: 'healthy',
            lastFired: new Date().toISOString(),
          },
        },
        uncoveredTools: {
          unprotected_api: 3,
        },
        lastUpdated: new Date().toISOString(),
      };

      fs.writeFileSync(customLedgerPath, JSON.stringify(sampleLedger), 'utf8');

      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      await runReport({ ledgerPath: customLedgerPath });

      const loggedText = consoleSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(loggedText).toContain('SQL-001');
      expect(loggedText).toContain('[HEALTHY]');
      expect(loggedText).toContain('Uncovered Tool Invocations (Policy Gaps)');
      expect(loggedText).toContain('unprotected_api');

      consoleSpy.mockRestore();
    });
  });

  describe('aegis license commands', () => {
    it('should display community status by default when no license is configured', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      runLicenseStatus();

      const loggedText = consoleSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(loggedText).toContain('Aegis License & Entitlements Status');
      expect(loggedText).toContain('COMMUNITY');
      expect(loggedText).toContain('@aegis/sql-guard');

      consoleSpy.mockRestore();
    });

    it('should activate valid enterprise license token and persist to .aegis/license.json', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      const manager = new AegisLicenseManager();
      const validToken = manager.generateLicenseKey({
        customerId: 'enterprise_org_123',
        customerEmail: 'admin@org.com',
        plan: 'enterprise',
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
        features: ['hipaa_guard', 'pci_dss_guard', 'soc2_guard'],
        maxMonthlyChecks: 'unlimited',
      });

      runLicenseActivate(validToken);

      const licenseFilePath = path.join(tempDir, '.aegis/license.json');
      expect(fs.existsSync(licenseFilePath)).toBe(true);

      const licenseData = JSON.parse(fs.readFileSync(licenseFilePath, 'utf8'));
      expect(licenseData.tier).toBe('enterprise');
      expect(licenseData.customerId).toBe('enterprise_org_123');

      consoleSpy.mockRestore();
    });
  });

  describe('aegis pricing command', () => {
    it('should print monetization tiers and Stripe checkout links', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      runPricing();

      const loggedText = consoleSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(loggedText).toContain('Aegis Invariant Kernel: Plans & Monetization Tiers');
      expect(loggedText).toContain('COMMUNITY');
      expect(loggedText).toContain('PRO');
      expect(loggedText).toContain('SCALE');
      expect(loggedText).toContain('ENTERPRISE');
      expect(loggedText).toContain('https://buy.stripe.com/aegis_pro_checkout');

      consoleSpy.mockRestore();
    });
  });

  describe('aegis pack commands', () => {
    it('should list all available rule packs and their entitlement status', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      runPackList();

      const loggedText = consoleSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(loggedText).toContain('Aegis Rule Pack Registry');
      expect(loggedText).toContain('@aegis/sql-guard');
      expect(loggedText).toContain('@aegis/hipaa-guard');
      expect(loggedText).toContain('@aegis/fintech-trade-guard');

      consoleSpy.mockRestore();
    });

    it('should validate a correctly formatted custom rule pack YAML', () => {
      const customPackYaml = path.join(tempDir, 'custom-guard.yaml');
      fs.writeFileSync(
        customPackYaml,
        `id: custom-guard\nname: Custom Test Guard\nversion: 1.0.0\nrules:\n  - id: CUST-01\n    severity: critical\n    description: Test rule\n    condition:\n      type: numeric\n      params:\n        field: val\n        max: 50\n`,
        'utf8'
      );

      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      runPackValidate(customPackYaml);

      const loggedText = consoleSpy.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(loggedText).toContain("Rule Pack 'Custom Test Guard' (v1.0.0) is VALID!");
      expect(loggedText).toContain('CUST-01');

      consoleSpy.mockRestore();
    });
  });

  describe('binary entrypoint validation', () => {
    it('should have executable bin script pointing to CJS bundle', () => {
      const binPath = path.resolve(__dirname, '../bin/aegis.js');
      expect(fs.existsSync(binPath)).toBe(true);
      const binContent = fs.readFileSync(binPath, 'utf8');
      expect(binContent).toContain('#!/usr/bin/env node');
      expect(binContent).toContain("require('../dist/index.js')");
    });
  });
});

