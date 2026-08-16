/**
 * Adversarial Fuzz Regression Suite
 *
 * Runs the deterministic evasion generator (hundreds of obfuscated variants
 * per base payload) and asserts:
 *   - ZERO false negatives (every malicious vector BLOCKED)
 *   - ZERO false positives (every benign vector ALLOWED)
 *
 * The corpus is seeded, so a passing run is reproducible; a failing run
 * names the exact generated vector that evaded or tripped the engine.
 */

import { describe, it, expect } from 'vitest';
import { AegisEngine } from '@aegis-kernel/core';
import { generateAdversarialCorpus } from '../src/evasion-generator.js';

const PACKS = [
  '@aegis/sql-guard',
  '@aegis/finance-guard',
  '@aegis/data-guard',
  '@aegis/hipaa-guard',
  '@aegis/pci-dss-guard',
  '@aegis/soc2-guard',
  '@aegis/eu-ai-act-guard',
  '@aegis/gdpr-guard',
  '@aegis/fintech-trade-guard',
];

describe('SQL tool-gating semantics', () => {
  it('does not flag SQL-looking text in non-DB tools (no false positives)', () => {
    const engine = new AegisEngine({ mode: 'enforce', packs: ['@aegis/sql-guard'] });
    const verdict = engine.evaluate({
      tool: 'search_kb',
      params: { query: 'DELETE FROM users' },
    });
    expect(verdict.allowed).toBe(true);
  });

  it('still blocks destructive SQL on database tools with generic query param', () => {
    const engine = new AegisEngine({ mode: 'enforce', packs: ['@aegis/sql-guard'] });
    const verdict = engine.evaluate({
      tool: 'database_exec',
      params: { query: 'DELETE FROM users WHERE 1=1' },
    });
    expect(verdict.allowed).toBe(false);
  });

  it('blocks destructive SQL even on oddly-named tools when the param is explicitly SQL', () => {
    const engine = new AegisEngine({ mode: 'enforce', packs: ['@aegis/sql-guard'] });
    const verdict = engine.evaluate({
      tool: 'custom_helper',
      params: { sql_query: 'DROP TABLE customers' },
    });
    expect(verdict.allowed).toBe(false);
  });
});

describe('Adversarial Evasion Fuzz (generated corpus)', () => {
  it('blocks every generated malicious vector with zero bypasses', () => {
    const engine = new AegisEngine({ mode: 'enforce', packs: PACKS });
    const corpus = generateAdversarialCorpus({ seed: 424242 });
    const malicious = corpus.filter((v) => v.type === 'malicious');

    const bypasses: string[] = [];
    for (const v of malicious) {
      const verdict = engine.evaluate(v.toolCall);
      if (verdict.allowed) {
        bypasses.push(`${v.id} [${v.name}] ${JSON.stringify(v.toolCall.params)}`);
      }
    }

    expect(bypasses).toEqual([]);
  });

  it('allows every generated benign vector with zero false positives', () => {
    const engine = new AegisEngine({ mode: 'enforce', packs: PACKS });
    const corpus = generateAdversarialCorpus({ seed: 424242 });
    const benign = corpus.filter((v) => v.type === 'benign');

    const falsePositives: string[] = [];
    for (const v of benign) {
      const verdict = engine.evaluate(v.toolCall);
      if (!verdict.allowed) {
        falsePositives.push(`${v.id} [${v.name}] ${JSON.stringify(v.toolCall.params)} -> ${JSON.stringify(verdict.violations.map((x) => x.ruleId))}`);
      }
    }

    expect(falsePositives).toEqual([]);
  });

  it('is deterministic: same seed produces the same corpus and verdicts', () => {
    const a = generateAdversarialCorpus({ seed: 12345 });
    const b = generateAdversarialCorpus({ seed: 12345 });
    expect(a.length).toBe(b.length);
    const bigintSafe = (_k: string, v: unknown) => (typeof v === 'bigint' ? v.toString() : v);
    for (let i = 0; i < a.length; i++) {
      expect(JSON.stringify(a[i].toolCall, bigintSafe)).toBe(JSON.stringify(b[i].toolCall, bigintSafe));
      // Fresh engine per vector: isolates stateful rules (rate-limit windows)
      // so we measure pure determinism, not cross-vector interference.
      const engine = new AegisEngine({ mode: 'enforce', packs: PACKS });
      const va = engine.evaluate(a[i].toolCall);
      const vb = engine.evaluate(b[i].toolCall);
      expect(va.allowed).toBe(vb.allowed);
      expect(va.violations.map((x) => x.ruleId)).toEqual(vb.violations.map((x) => x.ruleId));
      // proofHash is intentionally time-bound (non-replayable receipts), so
      // identical calls yield different hashes — verdicts must still match.
      expect(va.proofHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});
