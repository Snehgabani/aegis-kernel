import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  // Threat-intel feeds
  formatOpenDxlThreatMessage,
  RealTimeThreatIntelFeed,
  formatStixTaxiiIndicator,
  validateStixBundle,
  // WORM bundle exporter
  buildWormComplianceBundle,
  buildS3ObjectLockPutParams,
  buildGcsObjectRetentionMetadata,
  buildGcsBucketRetentionPolicy,
  verifyWormComplianceBundle,
  // JSON-LD Verifiable Credentials
  issueHitlVerifiableCredential,
  verifyHitlVerifiableCredential,
  buildHitlCredentialSubject,
  // Dossier + Merkle primitives
  generateComplianceDossier,
  computeEventChainMerkleRoot,
  generateAuditKeyPairEd25519,
  verifyDossierProof,
  renderComplianceMarkdown,
  renderComplianceHTML,
  renderCompliancePDF,
  type AegisEvent,
} from '@aegis-kernel/core';

/** SHA-256 hex of a seed, so fixtures carry realistic cryptographic hashes. */
function sha256(seed: string): string {
  return createHash('sha256').update(seed).digest('hex');
}

function makeBlockedEvent(id: string): AegisEvent {
  return {
    id,
    timestamp: '2026-08-16T01:30:00.000Z',
    version: '1.0.0',
    framework: 'langchain',
    toolName: 'execute_sql',
    toolCallFingerprint: sha256(`fingerprint:${id}`),
    mode: 'enforce',
    verdict: 'BLOCKED',
    rulesEvaluated: 12,
    rulesFired: [
      {
        ruleId: 'SQL-NO-DROP',
        packId: '@aegis/sql-guard',
        severity: 'critical',
        message: 'DROP TABLE statement prohibited by invariant policy',
      },
    ],
    latencyMs: 0.32,
    proofHash: sha256(`proof:${id}`),
    policyCommitmentHash: sha256('policy-hash-111'),
    userOverride: false,
  };
}

function makeAllowedEvent(id: string): AegisEvent {
  return { ...makeBlockedEvent(id), id, verdict: 'ALLOWED', rulesFired: [] };
}

/* ────────────────────────────────────────────────────────────────────────────
 * 1. Real-time STIX 2.1 & OpenDXL threat intelligence feeds
 * ──────────────────────────────────────────────────────────────────────────── */

describe('Real-time STIX 2.1 & OpenDXL threat intelligence feeds', () => {
  it('formats a blocked event into a valid OpenDXL message envelope', () => {
    const msg = formatOpenDxlThreatMessage(makeBlockedEvent('evt-1'), {
      topic: '/mcafee/event/aegis/threat',
      sourceClientId: 'aegis-node-01',
    });

    expect(msg).not.toBeNull();
    expect(msg!.topic).toBe('/mcafee/event/aegis/threat');
    expect(msg!.sourceClientId).toBe('aegis-node-01');
    expect(msg!.payloadType).toBe('threat-intel');
    expect(msg!.payload.kind).toBe('aegis-agent-threat');
    expect(msg!.payload.toolName).toBe('execute_sql');
    expect(msg!.payload.verdict).toBe('BLOCKED');
    expect(msg!.payload.ruleIds).toContain('SQL-NO-DROP');
    expect(msg!.payload.tlp).toBe('amber');
    expect(msg!.messageId).toMatch(/^dxl-msg-/);
  });

  it('returns null OpenDXL message for allowed/benign events', () => {
    expect(formatOpenDxlThreatMessage(makeAllowedEvent('evt-2'))).toBeNull();
  });

  it('emits STIX 2.1 bundles that pass RFC 4122 + patterning conformance', () => {
    const bundle = formatStixTaxiiIndicator(makeBlockedEvent('evt-stix'));
    expect(bundle).not.toBeNull();
    expect(bundle!.id).toMatch(/^bundle--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

    // First object is the producer identity; indicators carry created_by_ref.
    const identity = bundle!.objects[0];
    expect(identity.type).toBe('identity');
    expect(identity.id).toMatch(/^identity--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

    const indicator = bundle!.objects[1] as { id: string; pattern: string; created_by_ref?: string; object_marking_refs?: string[] };
    expect(indicator.id).toMatch(/^indicator--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    // Pattern is a single observation expression (no cross-SCO AND).
    expect(indicator.pattern).toBe("[process:name = 'execute_sql']");
    expect(indicator.created_by_ref).toBe(identity.id);
    // TLP:AMBER canonical marking referenced (never re-embedded).
    expect(indicator.object_marking_refs).toContain('marking-definition--f88d31f6-486f-44da-b317-01333bde0b82');
    expect(validateStixBundle(bundle!).valid).toBe(true);
  });

  it('streams deterministic STIX 2.1 + OpenDXL updates to subscribers in real time', () => {
    const feed = new RealTimeThreatIntelFeed();
    const received: unknown[] = [];

    const unsubscribe = feed.subscribe((update) => received.push(update));

    const update = feed.publish(makeBlockedEvent('evt-3'));
    feed.publish(makeAllowedEvent('evt-4'));

    expect(update.sequence).toBe(0);
    expect(update.stixBundle).not.toBeNull();
    expect(update.stixBundle!.type).toBe('bundle');
    expect(update.stixBundle!.objects[0].spec_version).toBe('2.1');
    expect(update.dxlMessage).not.toBeNull();
    expect(feed.subscriberCount).toBe(1);

    // Two updates received (one per published event), in sequence order.
    expect(received).toHaveLength(2);
    expect((received[0] as { sequence: number }).sequence).toBe(0);
    expect((received[1] as { sequence: number }).sequence).toBe(1);

    unsubscribe();
    expect(feed.subscriberCount).toBe(0);
  });

  it('suppresses STIX/DXL output for benign events but still emits a stream update', () => {
    const feed = new RealTimeThreatIntelFeed();
    const update = feed.publish(makeAllowedEvent('evt-5'));
    expect(update.stixBundle).toBeNull();
    expect(update.dxlMessage).toBeNull();
  });
});

/* ────────────────────────────────────────────────────────────────────────────
 * 2. WORM S3 / GCS Object Lock compliance bundle exporter
 * ──────────────────────────────────────────────────────────────────────────── */

describe('WORM (Write-Once Read-Many) S3 / GCS Object Lock compliance bundle', () => {
  const events: AegisEvent[] = [makeBlockedEvent('evt-a'), makeAllowedEvent('evt-b')];
  const dossier = generateComplianceDossier(events);

  it('builds a WORM bundle with hash-chained manifest and all dossier artifacts', () => {
    const bundle = buildWormComplianceBundle(
      dossier,
      { html: renderComplianceHTML, pdf: renderCompliancePDF },
      {
        provider: 'aws-s3',
        bucket: 'aegis-audit-lock',
        retention: { mode: 'COMPLIANCE', retainUntil: '2033-08-16T00:00:00.000Z', legalHold: true },
      }
    );

    expect(bundle.manifest.schema).toBe('aegis-worm-bundle/1.0');
    expect(bundle.provider).toBe('aws-s3');
    expect(bundle.files).toHaveLength(3); // json, html, pdf
    expect(bundle.files.map((f) => f.key).some((k) => k.endsWith('.json'))).toBe(true);
    expect(bundle.files.map((f) => f.key).some((k) => k.endsWith('.html'))).toBe(true);
    expect(bundle.files.map((f) => f.key).some((k) => k.endsWith('.pdf'))).toBe(true);
    expect(bundle.manifestSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(bundle.manifest.chainOfCustody).toHaveLength(3);

    // Every file carries a real SHA-256 digest.
    for (const f of bundle.files) {
      expect(f.sha256).toMatch(/^[a-f0-9]{64}$/);
      expect(f.sizeBytes).toBeGreaterThan(0);
    }
  });

  it('emits AWS S3 PutObject parameters with Object Lock (COMPLIANCE mode)', () => {
    const bundle = buildWormComplianceBundle(
      dossier,
      { html: renderComplianceHTML, pdf: renderCompliancePDF },
      { provider: 'aws-s3', retention: { mode: 'COMPLIANCE', retainUntil: '2033-08-16T00:00:00.000Z' } }
    );

    const params = buildS3ObjectLockPutParams(bundle.files[0], bundle.retention, 'aegis-audit-lock');
    expect(params.Bucket).toBe('aegis-audit-lock');
    expect(params.ObjectLockMode).toBe('COMPLIANCE');
    expect(params.ObjectLockRetainUntilDate).toBeInstanceOf(Date);
    expect(params.ContentType).toBe('application/json');
    expect(params.Body).toBeInstanceOf(Buffer);
  });

  it('emits GCS object retention metadata with Locked mode for COMPLIANCE', () => {
    const bundle = buildWormComplianceBundle(
      dossier,
      { html: renderComplianceHTML, pdf: renderCompliancePDF },
      {
        provider: 'gcp-gcs',
        retention: { mode: 'COMPLIANCE', retainUntil: '2033-08-16T00:00:00.000Z', legalHold: true },
      }
    );

    const meta = buildGcsObjectRetentionMetadata(bundle.files[0], bundle.retention);
    expect(meta.retention?.mode).toBe('Locked');
    expect(meta.retention?.retainUntilTime).toBe('2033-08-16T00:00:00.000Z');
    expect(meta.temporaryHold).toBe(true);
    expect(meta.metadata['aegis-sha256']).toBe(bundle.files[0].sha256);
  });

  it('emits the GCS bucket-level retentionPolicy (Object-Lock analog) with correct JSON API shape', () => {
    const policy = buildGcsBucketRetentionPolicy(
      { mode: 'COMPLIANCE', retainUntil: '2033-08-16T00:00:00.000Z' },
      '2026-08-16T00:00:00.000Z'
    );
    expect(policy.retentionPolicy.retentionPeriod).toMatch(/^\d+s$/);
    expect(policy.retentionPolicy.isLocked).toBe(true);

    const gov = buildGcsBucketRetentionPolicy(
      { mode: 'GOVERNANCE', retainUntil: '2033-08-16T00:00:00.000Z' },
      '2026-08-16T00:00:00.000Z'
    );
    expect(gov.retentionPolicy.isLocked).toBe(false);
  });

  it('detects tampering of the manifest itself (self-seal check)', () => {
    const bundle = buildWormComplianceBundle(
      dossier,
      { html: renderComplianceHTML, pdf: renderCompliancePDF },
      { provider: 'aws-s3', retention: { mode: 'GOVERNANCE', retainUntil: '2033-08-16T00:00:00.000Z' } }
    );

    // Mutate the manifest (e.g. rewrite a file size) without touching files.
    const tampered = {
      ...bundle,
      manifest: {
        ...bundle.manifest,
        files: bundle.manifest.files.map((f, i) => (i === 0 ? { ...f, sizeBytes: f.sizeBytes + 1 } : f)),
      },
    };

    const report = verifyWormComplianceBundle(tampered);
    expect(report.valid).toBe(false);
    expect(report.findings.some((f) => f.category === 'MANIFEST_SEAL' && f.status === 'FAIL')).toBe(true);
  });

  it('verifies an intact WORM bundle (all findings PASS)', () => {
    const bundle = buildWormComplianceBundle(
      dossier,
      { html: renderComplianceHTML, pdf: renderCompliancePDF },
      { provider: 'aws-s3', retention: { mode: 'GOVERNANCE', retainUntil: '2033-08-16T00:00:00.000Z' } }
    );

    const report = verifyWormComplianceBundle(bundle);
    expect(report.valid).toBe(true);
    expect(report.findings.every((f) => f.status === 'PASS')).toBe(true);
  });

  it('detects tampering of a WORM bundle artifact', () => {
    const bundle = buildWormComplianceBundle(
      dossier,
      { html: renderComplianceHTML, pdf: renderCompliancePDF },
      { provider: 'aws-s3', retention: { mode: 'COMPLIANCE', retainUntil: '2033-08-16T00:00:00.000Z' } }
    );

    // Tamper: mutate a file's content after hashing (simulate post-hoc rewrite).
    const tampered = {
      ...bundle,
      files: bundle.files.map((f, i) =>
        i === 0 ? { ...f, content: Buffer.from('tampered', 'utf8') } : f
      ),
    };

    const report = verifyWormComplianceBundle(tampered);
    expect(report.valid).toBe(false);
    expect(report.findings.some((f) => f.category === 'FILE_INTEGRITY' && f.status === 'FAIL')).toBe(true);
  });
});

/* ────────────────────────────────────────────────────────────────────────────
 * 3. JSON-LD Verifiable Credentials for HITL approval signatures
 * ──────────────────────────────────────────────────────────────────────────── */

describe('JSON-LD Verifiable Credentials for HITL approval signatures', () => {
  const { publicKey, privateKey } = generateAuditKeyPairEd25519();
  const event = makeBlockedEvent('evt-hitl-1');
  const subject = buildHitlCredentialSubject(
    event,
    'APPROVED',
    'jane.doe@example.com',
    'Compliance Officer',
    { ticketId: 'hitl-ticket-1', reason: 'Authorized high-risk migration' }
  );

  it('issues a structurally valid JSON-LD Verifiable Credential', () => {
    const vc = issueHitlVerifiableCredential(subject, {
      issuer: 'did:web:aegis-kernel.dev',
      issuerName: 'Aegis GRC Signing Authority',
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
      verificationMethod: 'did:web:aegis-kernel.dev#aegis-hitl-signing-key',
    });

    expect(vc['@context']).toContain('https://www.w3.org/2018/credentials/v1');
    expect(vc.type).toContain('VerifiableCredential');
    expect(vc.type).toContain('AegisHitlApprovalCredential');
    expect(vc.issuer.id).toBe('did:web:aegis-kernel.dev');
    expect(vc.credentialSubject.decision).toBe('APPROVED');
    expect(vc.credentialSubject.approver).toBe('jane.doe@example.com');
    expect(vc.proof.type).toBe('Ed25519Signature2020');
    expect(vc.proof.proofValue.startsWith('z')).toBe(true);
    expect(vc.proof.publicKeyMultibase?.startsWith('z')).toBe(true);
  });

  it('verifies a legitimate HITL credential against the issuer public key', () => {
    const vc = issueHitlVerifiableCredential(subject, {
      issuer: 'did:web:aegis-kernel.dev',
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });

    const result = verifyHitlVerifiableCredential(vc, publicKey);
    expect(result.valid).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.contextValid).toBe(true);
    expect(result.typeValid).toBe(true);
    expect(result.subjectValid).toBe(true);
  });

  it('rejects a tampered credential (decision flipped post-issuance)', () => {
    const vc = issueHitlVerifiableCredential(subject, {
      issuer: 'did:web:aegis-kernel.dev',
      privateKeyPem: privateKey,
      publicKeyPem: publicKey,
    });

    const tampered = {
      ...vc,
      credentialSubject: { ...vc.credentialSubject, decision: 'REJECTED' as const },
    };

    const result = verifyHitlVerifiableCredential(tampered, publicKey);
    expect(result.valid).toBe(false);
    expect(result.signatureValid).toBe(false);
  });

  it('rejects a credential signed by a different (untrusted) key', () => {
    const otherKeys = generateAuditKeyPairEd25519();
    const vc = issueHitlVerifiableCredential(subject, {
      issuer: 'did:web:aegis-kernel.dev',
      privateKeyPem: otherKeys.privateKey,
      publicKeyPem: otherKeys.publicKey,
    });

    const result = verifyHitlVerifiableCredential(vc, publicKey); // verify with OUR key, not theirs
    expect(result.valid).toBe(false);
    expect(result.signatureValid).toBe(false);
  });
});

/* ────────────────────────────────────────────────────────────────────────────
 * 4. End-to-end: dossier → WORM bundle → auditor verification
 * ──────────────────────────────────────────────────────────────────────────── */

describe('End-to-end compliance dossier pipeline for Big 4 auditors', () => {
  const events: AegisEvent[] = [
    makeBlockedEvent('evt-e2e-1'),
    makeAllowedEvent('evt-e2e-2'),
    makeAllowedEvent('evt-e2e-3'),
  ];

  it('does NOT claim Merkle validity in summary mode (events omitted)', () => {
    const dossier = generateComplianceDossier(events, [], '0'.repeat(64), { includeEvents: false });
    const verification = verifyDossierProof(dossier);
    // Without embedded events the root cannot be recomputed — honesty over assurance.
    expect(verification.merkleRootValid).toBe(false);
    expect(verification.valid).toBe(false);
    expect(verification.findings.some((f) => f.category === 'MERKLE_TREE' && f.status === 'WARN')).toBe(true);
  });

  it('produces a signed, verifiable dossier and WORM bundle from raw events', () => {
    const { publicKey, privateKey } = generateAuditKeyPairEd25519();

    const dossier = generateComplianceDossier(events, [], '0'.repeat(64), {
      signKey: privateKey,
      signAlgorithm: 'ed25519',
      publicKeyPem: publicKey,
      includeEvents: true,
    });

    // Merkle root recomputes from embedded events.
    const expectedRoot = computeEventChainMerkleRoot(events, '0'.repeat(64));
    expect(dossier.merkleRootHash).toBe(expectedRoot);

    // The verification public key is embedded for self-contained audit.
    expect(dossier.publicKeyPem).toBe(publicKey);

    // Dossier cryptographic proof verifies (Merkle + Ed25519 + control mapping).
    const verification = verifyDossierProof(dossier, publicKey);
    expect(verification.valid).toBe(true);
    expect(verification.merkleRootValid).toBe(true);
    expect(verification.signatureValid).toBe(true);
    expect(verification.controlCrosswalkValid).toBe(true);
    expect(verification.eventsAudited).toBe(3);

    // An auditor can verify using the embedded key alone (no external key).
    const selfContained = verifyDossierProof(dossier, dossier.publicKeyPem!);
    expect(selfContained.signatureValid).toBe(true);

    // WORM bundle round-trips and verifies.
    const bundle = buildWormComplianceBundle(
      dossier,
      { html: renderComplianceHTML, pdf: renderCompliancePDF },
      { provider: 'aws-s3', retention: { mode: 'COMPLIANCE', retainUntil: '2033-08-16T00:00:00.000Z' } }
    );
    expect(verifyWormComplianceBundle(bundle).valid).toBe(true);

    // All renderers emit non-empty artifacts.
    expect(renderComplianceMarkdown(dossier)).toContain('Executive GRC Compliance Dossier');
    expect(renderComplianceHTML(dossier)).toContain('<!DOCTYPE html>');
    expect(renderCompliancePDF(dossier).length).toBeGreaterThan(100);
    expect(renderCompliancePDF(dossier).subarray(0, 8).toString()).toBe('%PDF-1.4');
  });
});
