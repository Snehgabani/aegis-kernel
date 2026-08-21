/**
 * @file packages/core/src/telemetry/siem.ts
 * @description Enterprise SIEM & Threat Intelligence Telemetry Formatter.
 * Converts Aegis security events into CEF, RFC 5424 Syslog, Splunk HEC, and STIX 2.1 JSON
 * for Datadog, Splunk, Microsoft Sentinel, IBM QRadar, and CISA JCDC threat sharing.
 */

import { createHash } from 'node:crypto';
import type { AegisEvent } from '../types.js';

/**
 * RFC 4122 UUIDv5 generator (SHA-1 over a namespace UUID + name).
 *
 * STIX 2.1 (§2.9) requires object identifiers of the form `[type]--[UUID]`.
 * SDOs "SHOULD" use UUIDv4; UUIDv5 is explicitly permitted where a producer
 * needs deterministic, reproducible identifiers (here: auditable, re-runnable
 * threat-intel exports). Using a UUIDv5 derived from the event identity avoids
 * collisions and keeps the CTI feed byte-reproducible for compliance replay.
 */
export function uuidv5(
  name: string,
  namespace: string = 'a3b0c1d2-0000-4000-8000-000000000000'
): string {
  const nsHex = namespace.replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/i.test(nsHex)) {
    throw new Error('uuidv5 namespace must be a valid RFC 4122 UUID');
  }
  const nsBytes = Buffer.from(nsHex, 'hex');
  const hash = createHash('sha1').update(Buffer.concat([nsBytes, Buffer.from(name, 'utf8')])).digest();
  hash[6] = (hash[6] & 0x0f) | 0x50; // set version 5
  hash[8] = (hash[8] & 0x3f) | 0x80; // set variant 10xx
  const hex = hash.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

export interface SplunkHecEvent {
  time: number;
  host: string;
  source: string;
  sourcetype: string;
  index: string;
  event: Record<string, unknown>;
}

export interface StixDomainObject {
  type: string;
  spec_version: string;
  id: string;
  created: string;
  modified: string;
  name: string;
  description: string;
  indicator_types: string[];
  pattern: string;
  pattern_type: 'stix';
  valid_from: string;
  confidence: number;
  external_references?: { source_name: string; external_id: string; url?: string }[];
}

export interface StixBundle {
  type: 'bundle';
  id: string;
  objects: StixDomainObject[];
}

/**
 * Common Event Format (CEF) generator for ArcSight, Splunk, Microsoft Sentinel, QRadar.
 * Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
 */
export function formatCefEvent(event: AegisEvent): string {
  const severity = event.verdict === 'BLOCKED' ? 8 : 1;
  const violationRules = event.rulesFired.map((v) => v.ruleId).join(',') || 'NONE';
  const violationMsg = event.rulesFired.map((v) => v.message).join(' | ') || 'Action allowed';

  // Sanitize extension values (escape = and |)
  const sanitize = (val: string) => val.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/=/g, '\\=');

  const extensions: Record<string, string | number> = {
    act: event.verdict,
    app: event.framework || 'aegis-kernel',
    dhost: event.toolName,
    externalId: event.id,
    msg: sanitize(violationMsg),
    cs1: sanitize(event.toolCallFingerprint),
    cs1Label: 'ToolCallFingerprint',
    cs2: sanitize(event.proofHash),
    cs2Label: 'ProofHash',
    cs3: sanitize(event.policyCommitmentHash),
    cs3Label: 'PolicyCommitmentHash',
    cs4: sanitize(violationRules),
    cs4Label: 'RulesFired',
    cn1: event.latencyMs,
    cn1Label: 'LatencyMs',
    cn2: event.rulesEvaluated,
    cn2Label: 'RulesEvaluated',
  };

  const extensionStr = Object.entries(extensions)
    .map(([k, v]) => `${k}=${v}`)
    .join(' ');

  return `CEF:0|Aegis|Aegis-Invariant-Kernel|${event.version}|${event.verdict}|Agent Tool Call Evaluation|${severity}|${extensionStr}`;
}

/**
 * Syslog RFC 5424 structured syslog generator.
 * Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
 */
export function formatSyslogRfc5424(event: AegisEvent, hostname: string = 'aegis-host'): string {
  // Facility: local0 (16), Severity: Alert (1) for blocked, Notice (5) for allowed
  const pri = event.verdict === 'BLOCKED' ? 16 * 8 + 1 : 16 * 8 + 5;
  const timestamp = event.timestamp;
  const appName = 'aegis-kernel';
  const procId = process.pid || '-';
  const msgId = event.verdict;

  const sd = `[aegis@54321 id="${event.id}" tool="${event.toolName}" verdict="${event.verdict}" latencyMs="${event.latencyMs}" proofHash="${event.proofHash}"]`;
  const msg = event.verdict === 'BLOCKED'
    ? `SECURITY VIOLATION: Tool '${event.toolName}' was blocked. Violations: ${event.rulesFired.map((v) => `[${v.ruleId}] ${v.message}`).join('; ')}`
    : `TOOL CLEARED: Tool '${event.toolName}' satisfied all invariant policies.`;

  return `<${pri}>1 ${timestamp} ${hostname} ${appName} ${procId} ${msgId} ${sd} ${msg}`;
}

/**
 * Formats event for Splunk HTTP Event Collector (HEC).
 */
export function formatSplunkHecPayload(
  event: AegisEvent,
  options: { host?: string; source?: string; index?: string } = {}
): SplunkHecEvent {
  const epochTime = new Date(event.timestamp).getTime() / 1000;
  return {
    time: epochTime,
    host: options.host || 'aegis-node',
    source: options.source || 'aegis:kernel:eval',
    sourcetype: '_json',
    index: options.index || 'security',
    event: {
      aegis_event_id: event.id,
      timestamp: event.timestamp,
      tool_name: event.toolName,
      verdict: event.verdict,
      mode: event.mode,
      latency_ms: event.latencyMs,
      rules_evaluated: event.rulesEvaluated,
      rules_fired_count: event.rulesFired.length,
      rules_fired: event.rulesFired,
      proof_hash: event.proofHash,
      policy_hash: event.policyCommitmentHash,
      fingerprint: event.toolCallFingerprint,
    },
  };
}

/**
 * Converts security violations into standard STIX 2.1 Cyber Threat Intelligence (CTI) Indicator Bundle.
 * Enables automated threat feed sharing with CISA JCDC, MITRE ATLAS, and ISAC communities.
 */
export function formatStixTaxiiIndicator(event: AegisEvent): StixBundle | null {
  if (event.verdict !== 'BLOCKED' || event.rulesFired.length === 0) {
    return null;
  }

  // RFC 4122 UUIDv5-derived identifiers (STIX 2.1 §2.9 requires [type]--[UUID]).
  const bundleId = `bundle--${uuidv5(`aegis:event:${event.id}`)}`;
  const nowIso = new Date().toISOString();

  const indicators: StixDomainObject[] = event.rulesFired.map((violation, idx) => {
    const indicatorId = `indicator--${uuidv5(`aegis:event:${event.id}:rule:${idx}:${violation.ruleId}`)}`;
    // STIX patterning grammar (§9): a single observation expression `[...]`
    // must not mix multiple SCO types. The observable that signals the misuse
    // is the invoked tool (process); the Merkle proof hash is carried as an
    // external reference rather than a fabricated `file:hashes` entry.
    const pattern = `[process:name = '${event.toolName.replace(/'/g, "\\'")}']`;
    return {
      type: 'indicator',
      spec_version: '2.1',
      id: indicatorId,
      created: nowIso,
      modified: nowIso,
      name: `Adversarial AI Agent Tool Misuse: ${violation.ruleId}`,
      description: `Aegis Invariant Kernel intercepted an unauthorized agent tool invocation on '${event.toolName}'. Violation: ${violation.message}`,
      indicator_types: ['anomalous-activity', 'malicious-activity'],
      pattern,
      pattern_type: 'stix',
      pattern_version: '2.1',
      valid_from: event.timestamp,
      confidence: 95,
      external_references: [
        {
          source_name: 'mitre-atlas',
          external_id: 'AML.T0053',
          url: 'https://atlas.mitre.org/techniques/AML.T0053',
        },
        {
          source_name: 'owasp-agentic',
          external_id: 'ASI02',
          url: 'https://genai.owasp.org',
        },
        {
          source_name: 'aegis-kernel',
          external_id: `proof:${event.proofHash}`,
        },
      ],
    };
  });

  return {
    type: 'bundle',
    id: bundleId,
    objects: indicators,
  };
}

/**
 * Structural conformance check for a STIX 2.1 bundle: identifier format,
 * required indicator fields, and pattern_type. Useful as a pre-publish
 * gate for TAXII / CISA JCDC submission.
 */
export function validateStixBundle(bundle: StixBundle): { valid: boolean; findings: string[] } {
  const findings: string[] = [];

  if (bundle.type !== 'bundle') findings.push('bundle.type must be "bundle".');
  if (!/^bundle--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(bundle.id)) {
    findings.push('bundle.id must be bundle--<RFC4122 UUID>.');
  }
  if (!Array.isArray(bundle.objects) || bundle.objects.length === 0) {
    findings.push('bundle.objects must be a non-empty array.');
  }

  for (const obj of bundle.objects) {
    if (!/^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(obj.id)) {
      findings.push(`${obj.type} id must be <type>--<RFC4122 UUID>.`);
    }
    if (obj.spec_version !== '2.1') findings.push(`${obj.id} spec_version must be "2.1".`);
    if (obj.type === 'indicator') {
      if (obj.pattern_type !== 'stix') findings.push(`${obj.id} pattern_type must be "stix".`);
      if (typeof obj.pattern !== 'string' || !obj.pattern.startsWith('[')) {
        findings.push(`${obj.id} pattern must be a bracketed STIX pattern expression.`);
      }
      if (typeof obj.valid_from !== 'string') findings.push(`${obj.id} missing valid_from.`);
    }
  }

  return { valid: findings.length === 0, findings };
}
