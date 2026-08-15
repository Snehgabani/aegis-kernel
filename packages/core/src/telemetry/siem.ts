/**
 * @file packages/core/src/telemetry/siem.ts
 * @description Enterprise SIEM & Threat Intelligence Telemetry Formatter.
 * Converts Aegis security events into CEF, RFC 5424 Syslog, Splunk HEC, and STIX 2.1 JSON
 * for Datadog, Splunk, Microsoft Sentinel, IBM QRadar, and CISA JCDC threat sharing.
 */

import type { AegisEvent } from '../types.js';

export interface SplunkHecEvent {
  time: number;
  host: string;
  source: string;
  sourcetype: string;
  index: string;
  event: Record<string, unknown>;
}

export interface StixCyberObservable {
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
  spec_version: '2.1';
  objects: StixCyberObservable[];
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

  const bundleId = `bundle--${event.id}`;
  const nowIso = new Date().toISOString();

  const indicators: StixCyberObservable[] = event.rulesFired.map((violation, idx) => {
    const indicatorId = `indicator--${event.id.slice(0, 30)}-${idx}`;
    return {
      type: 'indicator',
      spec_version: '2.1',
      id: indicatorId,
      created: nowIso,
      modified: nowIso,
      name: `Adversarial AI Agent Tool Misuse: ${violation.ruleId}`,
      description: `Aegis Invariant Kernel intercepted an unauthorized agent tool invocation on '${event.toolName}'. Violation: ${violation.message}`,
      indicator_types: ['anomalous-activity', 'malicious-activity'],
      pattern: `[process:name = '${event.toolName}' AND file:hashes.'SHA-256' = '${event.proofHash}']`,
      pattern_type: 'stix',
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
      ],
    };
  });

  return {
    type: 'bundle',
    id: bundleId,
    spec_version: '2.1',
    objects: indicators,
  };
}
