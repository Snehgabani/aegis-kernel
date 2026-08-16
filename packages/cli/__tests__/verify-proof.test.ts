import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  AegisEngine,
  generateComplianceDossier,
  signComplianceDossier,
  generateAuditKeyPairEd25519,
  type AegisEvent,
} from '@aegis-kernel/core';
import { runVerifyProof } from '../src/verify-proof-cli.js';

describe('Aegis CLI — Proof Verification & CPA Ledger Validator', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-proof-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should successfully verify a valid unsigned compliance dossier', () => {
    const engine = new AegisEngine();
    // Simulate events
    engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT id, name FROM users WHERE active = 1' } });
    engine.evaluate({ tool: 'sql_query', params: { query: 'DROP TABLE users' } }); // blocked

    const events: AegisEvent[] = engine.getRecentEvents(10);
    const dossier = generateComplianceDossier(events, engine.getLoadedPacks());

    const dossierPath = path.join(tmpDir, 'valid-dossier.json');
    fs.writeFileSync(dossierPath, JSON.stringify(dossier, null, 2), 'utf8');

    const result = runVerifyProof(dossierPath);
    expect(result.ok).toBe(true);
    expect(result.report).toBeDefined();
    expect(result.report?.merkleRootValid).toBe(true);
    expect(result.report?.controlCrosswalkValid).toBe(true);
    expect(result.report?.controlCoverage.satisfied).toBeGreaterThan(10);
  });

  it('should successfully verify an HMAC-SHA256 signed compliance dossier', () => {
    const engine = new AegisEngine();
    engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT name FROM customers' } });

    const secret = 'corporate-audit-secret-key-2026';
    const dossier = generateComplianceDossier(engine.getRecentEvents(10), engine.getLoadedPacks(), '0'.repeat(64), {
      signKey: secret,
      signAlgorithm: 'hmac-sha256',
    });

    const dossierPath = path.join(tmpDir, 'signed-hmac-dossier.json');
    fs.writeFileSync(dossierPath, JSON.stringify(dossier, null, 2), 'utf8');

    // 1. Verify with correct secret
    const passResult = runVerifyProof(dossierPath, { key: secret });
    expect(passResult.ok).toBe(true);
    expect(passResult.report?.signatureValid).toBe(true);
    expect(passResult.report?.signatureAlgorithm).toBe('HMAC_SHA256');

    // 2. Verify with incorrect secret
    const failResult = runVerifyProof(dossierPath, { key: 'wrong-secret-key' });
    expect(failResult.ok).toBe(false);
    expect(failResult.report?.signatureValid).toBe(false);
  });

  it('should successfully verify an Ed25519 asymmetric signed compliance dossier', () => {
    const engine = new AegisEngine();
    engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT balance FROM accounts WHERE user_id = 42' } });

    const { publicKey, privateKey } = generateAuditKeyPairEd25519();
    const dossier = generateComplianceDossier(engine.getRecentEvents(10), engine.getLoadedPacks(), '0'.repeat(64), {
      signKey: privateKey,
      signAlgorithm: 'ed25519',
    });

    const dossierPath = path.join(tmpDir, 'signed-ed25519-dossier.json');
    fs.writeFileSync(dossierPath, JSON.stringify(dossier, null, 2), 'utf8');

    // 1. Verify with correct public key
    const passResult = runVerifyProof(dossierPath, { key: publicKey });
    expect(passResult.ok).toBe(true);
    expect(passResult.report?.signatureValid).toBe(true);
    expect(passResult.report?.signatureAlgorithm).toBe('ED25519');

    // 2. Verify with a different public key
    const otherKeys = generateAuditKeyPairEd25519();
    const failResult = runVerifyProof(dossierPath, { key: otherKeys.publicKey });
    expect(failResult.ok).toBe(false);
    expect(failResult.report?.signatureValid).toBe(false);
  });

  it('should detect tampering in event log history (Merkle root mismatch)', () => {
    const engine = new AegisEngine();
    engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT email FROM leads' } });
    engine.evaluate({ tool: 'sql_query', params: { query: 'DROP DATABASE production' } });

    const events = engine.getRecentEvents(10);
    const dossier = generateComplianceDossier(events, engine.getLoadedPacks());

    // Tamper with the recorded events (e.g. change a BLOCKED event to ALLOWED)
    if (dossier.events && dossier.events.length > 0) {
      dossier.events[0].verdict = 'ALLOWED';
      dossier.events[0].toolName = 'tampered_tool';
    }

    const dossierPath = path.join(tmpDir, 'tampered-dossier.json');
    fs.writeFileSync(dossierPath, JSON.stringify(dossier, null, 2), 'utf8');

    const result = runVerifyProof(dossierPath);
    expect(result.ok).toBe(false);
    expect(result.report?.merkleRootValid).toBe(false);
  });

  it('should return error for non-existent file or corrupted JSON', () => {
    const missingRes = runVerifyProof('/tmp/non-existent-file-12345.json');
    expect(missingRes.ok).toBe(false);
    expect(missingRes.error).toContain('File not found');

    const corruptPath = path.join(tmpDir, 'corrupt.json');
    fs.writeFileSync(corruptPath, '{ corrupt json invalid', 'utf8');
    const corruptRes = runVerifyProof(corruptPath);
    expect(corruptRes.ok).toBe(false);
    expect(corruptRes.error).toContain('Invalid JSON');
  });

  it('should output JSON when --json option is provided', () => {
    const engine = new AegisEngine();
    engine.evaluate({ tool: 'sql_query', params: { query: 'SELECT 1' } });
    const dossier = generateComplianceDossier(engine.getRecentEvents(10), engine.getLoadedPacks());

    const dossierPath = path.join(tmpDir, 'json-opt-dossier.json');
    fs.writeFileSync(dossierPath, JSON.stringify(dossier, null, 2), 'utf8');

    const result = runVerifyProof(dossierPath, { json: true });
    expect(result.ok).toBe(true);
    expect(result.report?.dossierId).toBe(dossier.dossierId);
  });
});
