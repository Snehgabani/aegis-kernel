/**
 * @file packages/core/src/compliance/threat-intel-feed.ts
 * @description Real-time STIX 2.1 (TAXII) and OpenDXL threat intelligence feed
 * exporter. Streams intercepted adversarial AI-agent tool-call events to
 * enterprise SOC/GRC subscribers as machine-readable CTI, in-process and
 * zero-egress (the caller owns every sink).
 *
 *   - STIX 2.1:   `indicator` SDOs inside a `bundle` (TAXII / CISA JCDC style).
 *   - OpenDXL:    McAfee Open Data Exchange Layer message envelope carrying a
 *                 JSON threat payload on a publish/subscribe topic.
 */

import { randomUUID } from 'node:crypto';
import type { AegisEvent } from '../types.js';
import { formatStixTaxiiIndicator, type StixBundle } from '../telemetry/siem.js';

/* ────────────────────────────────────────────────────────────────────────────
 * OpenDXL message envelope.
 * ──────────────────────────────────────────────────────────────────────────── */

export interface DxlThreatPayload {
  kind: 'aegis-agent-threat';
  specVersion: '1.0';
  id: string;
  indicatorId?: string;
  eventId: string;
  toolName: string;
  verdict: 'BLOCKED';
  ruleIds: string[];
  severity: string;
  message: string;
  proofHash: string;
  policyCommitmentHash: string;
  occurredAt: string;
  tlp: 'red' | 'amber' | 'green' | 'white';
  externalReferences: { sourceName: string; externalId: string; url?: string }[];
}

export interface OpenDxlThreatMessage {
  topic: string;
  sourceClientId: string;
  sourceTenantGuid: string;
  messageId: string;
  payloadType: 'threat-intel';
  publishedAt: string;
  payload: DxlThreatPayload;
}

export interface OpenDxlOptions {
  topic?: string;
  sourceClientId?: string;
  sourceTenantGuid?: string;
  tlp?: DxlThreatPayload['tlp'];
}

/**
 * Formats a blocked Aegis event into an OpenDXL (Open Data Exchange Layer)
 * publish/subscribe threat-intelligence message.
 */
export function formatOpenDxlThreatMessage(
  event: AegisEvent,
  options: OpenDxlOptions = {}
): OpenDxlThreatMessage | null {
  if (event.verdict !== 'BLOCKED' || event.rulesFired.length === 0) {
    return null;
  }

  const indicator = formatStixTaxiiIndicator(event);
  const firstIndicator = indicator?.objects[0];

  const payload: DxlThreatPayload = {
    kind: 'aegis-agent-threat',
    specVersion: '1.0',
    id: `dxl-${randomUUID()}`,
    indicatorId: firstIndicator?.id,
    eventId: event.id,
    toolName: event.toolName,
    verdict: 'BLOCKED',
    ruleIds: event.rulesFired.map((v) => v.ruleId),
    severity: event.rulesFired.map((v) => v.severity).includes('critical') ? 'critical' : 'high',
    message: event.rulesFired.map((v) => v.message).join(' | '),
    proofHash: event.proofHash,
    policyCommitmentHash: event.policyCommitmentHash,
    occurredAt: event.timestamp,
    tlp: options.tlp ?? 'amber',
    externalReferences: [
      { sourceName: 'mitre-atlas', externalId: 'AML.T0053', url: 'https://atlas.mitre.org/techniques/AML.T0053' },
      { sourceName: 'owasp-agentic', externalId: 'ASI02', url: 'https://genai.owasp.org' },
    ],
  };

  return {
    topic: options.topic ?? '/aegis/event/threat-intel/agent-tool-misuse',
    sourceClientId: options.sourceClientId ?? `aegis-kernel-${randomUUID()}`,
    sourceTenantGuid: options.sourceTenantGuid ?? 'aegis-enterprise',
    messageId: `dxl-msg-${randomUUID()}`,
    payloadType: 'threat-intel',
    publishedAt: new Date().toISOString(),
    payload,
  };
}

/* ────────────────────────────────────────────────────────────────────────────
 * Real-time streaming feed.
 * ──────────────────────────────────────────────────────────────────────────── */

export interface ThreatIntelUpdate {
  sequence: number;
  emittedAt: string;
  eventId: string;
  stixBundle: StixBundle | null;
  dxlMessage: OpenDxlThreatMessage | null;
}

export type ThreatIntelListener = (update: ThreatIntelUpdate) => void;

/**
 * A zero-dependency, in-process pub/sub feed that converts every evaluated
 * event into STIX 2.1 + OpenDXL intelligence and fans it out to subscribers.
 * Subscribers are synchronous and receive the *same* deterministic update the
 * publisher produces — ideal for mirroring to a SIEM or TAXII server.
 */
export class RealTimeThreatIntelFeed {
  private listeners = new Set<ThreatIntelListener>();
  private sequence = 0;

  /** Registers a listener; returns an unsubscribe function. */
  public subscribe(listener: ThreatIntelListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Number of active subscribers. */
  public get subscriberCount(): number {
    return this.listeners.size;
  }

  /**
   * Evaluates an event into STIX 2.1 + OpenDXL intelligence, fans it out to all
   * subscribers, and returns the deterministic update (sequence-stamped).
   */
  public publish(event: AegisEvent, dxlOptions: OpenDxlOptions = {}): ThreatIntelUpdate {
    const update: ThreatIntelUpdate = {
      sequence: this.sequence++,
      emittedAt: new Date().toISOString(),
      eventId: event.id,
      stixBundle: formatStixTaxiiIndicator(event),
      dxlMessage: formatOpenDxlThreatMessage(event, dxlOptions),
    };

    for (const listener of this.listeners) {
      try {
        listener(update);
      } catch {
        // A misbehaving subscriber must never break the security feed.
      }
    }

    return update;
  }

  /** Removes all subscribers and resets the sequence. */
  public clear(): void {
    this.listeners.clear();
    this.sequence = 0;
  }
}
