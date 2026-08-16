import { describe, it, expect } from 'vitest';
import { AegisEngine } from '../src/engine.js';
import { AegisSanitizer } from '../src/sanitizer.js';
import { SqlChecker, HOMOGLYPH_DECODE_MAP } from '../src/checkers/sql-checker.js';
import type { ToolCall } from '../src/types.js';

describe('Aegis Adversarial Fuzzing & Unicode Mutation Suite', () => {
  const engine = new AegisEngine({
    mode: 'enforce',
    packs: ['@aegis/sql-guard', '@aegis/data-guard', '@aegis/finance-guard'],
  });
  const checker = new SqlChecker();

  // =========================================================================
  // 1. Cyrillic & Greek Homoglyphs in SQL Keywords
  // =========================================================================
  describe('Cyrillic & Greek Homoglyph Evasion', () => {
    const homoglyphMaliciousQueries = [
      { name: 'Cyrillic small te in DELETE', sql: 'dele\u0442e from users' },
      { name: 'Cyrillic capital Te in TRUNCATE', sql: '\u0422RUNCATE TABLE users' },
      { name: 'Cyrillic small te in TRUNCATE', sql: '\u0442runcate table users' },
      { name: 'Cyrillic small es in DELETE', sql: 'del\u0435t\u0435 from users' },
      { name: 'Cyrillic small o in DROP', sql: 'dr\u043Ep table users' },
      { name: 'Cyrillic small a in ALTER', sql: '\u0430lter table users drop column ssn' },
      { name: 'Cyrillic small de (Komi) in DROP', sql: '\u0501rop table users' },
      { name: 'Cyrillic small ghe in DROP', sql: 'd\u0433op table users' },
      { name: 'Cyrillic small em in DROP', sql: 'drop table \u043Cembers' },
      { name: 'Greek lunate sigma in multi-statement query', sql: 'sele\u03F2t 1; drop table users;' },
      { name: 'Greek lunate sigma in DROP', sql: 'drop table \u03F2ustomers' },
      { name: 'Greek alpha & epsilon in DELETE', sql: 'd\u03B5l\u03B5t\u03B5 from users' },
      { name: 'Greek sigma in DROP', sql: '\u03C3elect 1; drop table users;' },
      { name: 'Mixed Cyrillic & Greek in UPDATE', sql: 'upd\u0430\u03C4\u0435 users set role=\'admin\'' },
      { name: 'Full Cyrillic homoglyph DELETE', sql: '\u0434\u0435\u043B\u0435\u0442\u0435 from users' },
    ];

    for (const v of homoglyphMaliciousQueries) {
      it(`should block homoglyph destructive vector: ${v.name} ("${v.sql}")`, () => {
        const toolCall: ToolCall = {
          tool: 'database_exec',
          params: { query: v.sql },
        };
        const verdict = engine.evaluate(toolCall);
        expect(verdict.allowed).toBe(false);
        expect(verdict.violations.length).toBeGreaterThan(0);
      });
    }
  });

  // =========================================================================
  // 2. Bidirectional Override (BiDi) & Invisible Format Control Attacks
  // =========================================================================
  describe('Bidirectional (BiDi) & Invisible Controls', () => {
    const bidiQueries = [
      { name: 'Right-to-Left Isolate (RLI) in DELETE', sql: 'D\u2067E\u2067L\u2067E\u2067T\u2067E FROM users' },
      { name: 'Left-to-Right Isolate (LRI) in DROP', sql: 'D\u2066R\u2066O\u2066P TABLE users' },
      { name: 'First Strong Isolate (FSI) in TRUNCATE', sql: 'T\u2068R\u2068U\u2068N\u2068C\u2068A\u2068T\u2068E TABLE users' },
      { name: 'Pop Directional Isolate (PDI) in ALTER', sql: 'A\u2069L\u2069T\u2069E\u2069R TABLE users DROP COLUMN ssn' },
      { name: 'Arabic Letter Mark (ALM) in DELETE', sql: 'D\u061CE\u061CL\u061CE\u061CT\u061CE FROM users' },
      { name: 'Right-to-Left Override (RLO) in DROP', sql: 'D\u202EROP TABLE users' },
      { name: 'Left-to-Right Mark (LRM) in TRUNCATE', sql: 'T\u200ER\u200EU\u200EN\u200EC\u200EA\u200ET\u200EE TABLE users' },
      { name: 'Right-to-Left Mark (RLM) in DELETE', sql: 'D\u200FE\u200FL\u200FE\u200FT\u200FE FROM users' },
    ];

    for (const v of bidiQueries) {
      it(`should block BiDi obfuscated destructive vector: ${v.name}`, () => {
        const toolCall: ToolCall = {
          tool: 'database_exec',
          params: { query: v.sql },
        };
        const verdict = engine.evaluate(toolCall);
        expect(verdict.allowed).toBe(false);
        expect(verdict.violations.length).toBeGreaterThan(0);
      });
    }
  });

  // =========================================================================
  // 3. Zero-Width & Invisible Character Injections
  // =========================================================================
  describe('Zero-Width & Invisible Character Injections', () => {
    const zeroWidthQueries = [
      { name: 'Zero-Width Space (ZWSP)', sql: 'D\u200BE\u200BL\u200BE\u200BT\u200BE FROM users' },
      { name: 'Zero-Width Non-Joiner (ZWNJ)', sql: 'D\u200CE\u200CL\u200CE\u200CT\u200CE FROM users' },
      { name: 'Zero-Width Joiner (ZWJ)', sql: 'D\u200DE\u200DL\u200DE\u200DT\u200DE FROM users' },
      { name: 'Word Joiner (WJ)', sql: 'D\u2060R\u2060O\u2060P TABLE users' },
      { name: 'Invisible Separator', sql: 'T\u2063R\u2063U\u2063N\u2063C\u2063A\u2063T\u2063E TABLE users' },
      { name: 'Soft Hyphen (SHY)', sql: 'D\u00ADE\u00ADL\u00ADE\u00ADT\u00ADE FROM users' },
      { name: 'Combining Grapheme Joiner (CGJ)', sql: 'D\u034FR\u034FO\u034FP TABLE users' },
      { name: 'Mongolian Vowel Separator', sql: 'D\u180EE\u180EL\u180EE\u180ET\u180EE FROM users' },
      { name: 'Hangul Filler', sql: 'D\u115FR\u115FO\u115FP TABLE users' },
      { name: 'Halfwidth Hangul Filler', sql: 'T\uFFA0R\uFFA0U\uFFA0N\uFFA0C\uFFA0A\uFFA0T\uFFA0E TABLE users' },
      { name: 'Byte Order Mark (BOM)', sql: '\uFEFFDROP \uFEFFTABLE \uFEFFusers' },
    ];

    for (const v of zeroWidthQueries) {
      it(`should block zero-width injected vector: ${v.name}`, () => {
        const toolCall: ToolCall = {
          tool: 'database_exec',
          params: { query: v.sql },
        };
        const verdict = engine.evaluate(toolCall);
        expect(verdict.allowed).toBe(false);
        expect(verdict.violations.length).toBeGreaterThan(0);
      });
    }
  });

  // =========================================================================
  // 4. Nested Comment Splits & MySQL Conditional Comment Injections
  // =========================================================================
  describe('Nested Comment Splits & MySQL Conditional Comments', () => {
    const commentQueries = [
      { name: 'Nested comment in DELETE keyword', sql: 'DE/*/*nested*/*/LETE FROM users' },
      { name: 'Nested comment in DROP keyword', sql: 'D/*/*x*/*/ROP TABLE users' },
      { name: 'Nested comment in TRUNCATE keyword', sql: 'TRUN/*/*x*/*/CATE TABLE users' },
      { name: 'Multiple nested comments in every character', sql: 'D/*/*1*/*/E/*/*2*/*/L/*/*3*/*/E/*/*4*/*/T/*/*5*/*/E FROM users' },
      { name: 'Nested comments hiding entire query', sql: '/* outer /* inner */ */ DELETE FROM users' },
      { name: 'Comment split in TABLE keyword', sql: 'DROP T/**/A/**/B/**/L/**/E users' },
      { name: 'Comment split in DATABASE keyword', sql: 'DROP D/**/A/**/T/**/A/**/B/**/A/**/S/**/E prod' },
      { name: 'MySQL versioned conditional comment DROP', sql: 'SELECT 1; /*!50000 DROP TABLE users; */' },
      { name: 'MySQL versioned conditional comment DELETE', sql: '/*!50000 DELETE FROM users; */' },
      { name: 'MySQL unversioned conditional comment DELETE tautology', sql: '/*!DELETE FROM users WHERE 1=1*/' },
      { name: 'MySQL conditional comment inside ALTER TABLE', sql: '/*!ALTER TABLE users DROP COLUMN ssn*/' },
      { name: 'Comment-split in WHERE clause', sql: 'DELETE FROM users W/**/H/**/E/**/R/**/E 1=1' },
      { name: 'Comment-split in FROM clause', sql: 'DELETE F/**/R/**/O/**/M users' },
    ];

    for (const v of commentQueries) {
      it(`should block comment obfuscated vector: ${v.name}`, () => {
        const toolCall: ToolCall = {
          tool: 'database_exec',
          params: { query: v.sql },
        };
        const verdict = engine.evaluate(toolCall);
        expect(verdict.allowed).toBe(false);
        expect(verdict.violations.length).toBeGreaterThan(0);
      });
    }
  });

  // =========================================================================
  // 5. AegisSanitizer Parameter Normalization & Redaction Under Attack
  // =========================================================================
  describe('AegisSanitizer Parameter Mutations & Auto-Rewriting', () => {
    it('should redact Credit Card with BiDi RLI injections', () => {
      const toolCall: ToolCall = {
        tool: 'send_message',
        params: { text: 'Card: 4\u20671\u20671\u20671-1111-1111-1111' },
      };
      const res = AegisSanitizer.sanitize(toolCall);
      expect(res.wasModified).toBe(true);
      expect(res.sanitized.params.text).toContain('[REDACTED_CREDIT_CARD]');
      expect(res.sanitized.params.text).not.toContain('4111');
    });

    it('should redact SSN with Combining Grapheme Joiners (CGJ)', () => {
      const toolCall: ToolCall = {
        tool: 'send_message',
        params: { text: 'SSN: 1\u034F2\u034F3-45-6789' },
      };
      const res = AegisSanitizer.sanitize(toolCall);
      expect(res.wasModified).toBe(true);
      expect(res.sanitized.params.text).toContain('[REDACTED_SSN]');
    });

    it('should redact Credit Card with Mongolian Vowel Separators', () => {
      const toolCall: ToolCall = {
        tool: 'send_message',
        params: { text: 'Card: 4111\u180E1111\u180E1111\u180E1111' },
      };
      const res = AegisSanitizer.sanitize(toolCall);
      expect(res.wasModified).toBe(true);
      expect(res.sanitized.params.text).toContain('[REDACTED_CREDIT_CARD]');
    });

    it('should inject mandatory LIMIT 100 on Cyrillic homoglyph SELECT query', () => {
      const toolCall: ToolCall = {
        tool: 'query_db',
        params: { query: 'S\u0415L\u0415CT * FROM users' },
      };
      const res = AegisSanitizer.sanitize(toolCall);
      expect(res.wasModified).toBe(true);
      expect(res.sanitized.params.query).toBe('SELECT * FROM users LIMIT 100;');
    });

    it('should inject mandatory LIMIT 100 on fullwidth Unicode SELECT query', () => {
      const toolCall: ToolCall = {
        tool: 'query_db',
        params: { query: 'ＳＥＬＥＣＴ * FROM users' },
      };
      const res = AegisSanitizer.sanitize(toolCall);
      expect(res.wasModified).toBe(true);
      expect(res.sanitized.params.query).toBe('SELECT * FROM users LIMIT 100;');
    });
  });

  // =========================================================================
  // 6. Combinatorial Multi-Vector Adversarial Fuzzing (100% Rejection Proof)
  // =========================================================================
  describe('Combinatorial Multi-Vector Adversarial Fuzzing (100% Rejection Proof)', () => {
    const basePayloads = [
      'DELETE FROM users',
      'DELETE FROM users WHERE 1=1',
      'DROP TABLE users',
      'DROP TABLE IF EXISTS users',
      'DROP DATABASE production',
      'TRUNCATE TABLE users',
      'ALTER TABLE users DROP COLUMN password_hash',
      'UPDATE users SET role = "admin"',
      'UPDATE users SET role = "admin" WHERE 1=1',
    ];

    const mutations: Array<{ name: string; mutate: (sql: string) => string }> = [
      {
        name: 'Cyrillic e/a/o substitution',
        mutate: (s) => s.replace(/e/gi, '\u0435').replace(/a/gi, '\u0430').replace(/o/gi, '\u043E'),
      },
      {
        name: 'Cyrillic t substitution',
        mutate: (s) => s.replace(/t/gi, '\u0442'),
      },
      {
        name: 'Greek lunate sigma & alpha substitution',
        mutate: (s) => s.replace(/c/gi, '\u03F2').replace(/a/gi, '\u03B1'),
      },
      {
        name: 'BiDi RLI insertion between characters',
        mutate: (s) => s.split(' ').map((w) => w.split('').join('\u2067')).join(' '),
      },
      {
        name: 'BiDi ALM insertion',
        mutate: (s) => s.split(' ').map((w) => w.split('').join('\u061C')).join(' '),
      },
      {
        name: 'Zero-Width Non-Joiner insertion',
        mutate: (s) => s.split(' ').map((w) => w.split('').join('\u200C')).join(' '),
      },
      {
        name: 'Combining Grapheme Joiner insertion',
        mutate: (s) => s.split(' ').map((w) => w.split('').join('\u034F')).join(' '),
      },
      {
        name: 'Nested comment splitting in keywords',
        mutate: (s) => s.replace(/\b([A-Z]{3,})\b/gi, (_, kw) => {
          const mid = Math.floor(kw.length / 2);
          return kw.slice(0, mid) + '/*/*x*/*/' + kw.slice(mid);
        }),
      },
      {
        name: 'MySQL conditional comment wrapping',
        mutate: (s) => `/*!50000 ${s} */`,
      },
      {
        name: 'Fullwidth Unicode + Zero-Width + Nested Comments combined',
        mutate: (s) => {
          let out = s.replace(/DELETE/gi, 'Ｄ\u200B/*/*n*/*/ＥＬＥＴＥ');
          out = out.replace(/DROP/gi, 'Ｄ\u2060/*/*x*/*/ＲＯＰ');
          out = out.replace(/TRUNCATE/gi, 'Ｔ\u034F/*/*y*/*/ＲＵＮＣＡＴＥ');
          out = out.replace(/TABLE/gi, 'Ｔ/*a*/Ａ/*b*/Ｂ/*c*/Ｌ/*d*/Ｅ');
          return out;
        },
      },
    ];

    let totalTested = 0;
    let totalBlocked = 0;

    for (const base of basePayloads) {
      for (const m of mutations) {
        const mutated = m.mutate(base);
        it(`[${m.name}] on "${base}" -> 100% rejection`, () => {
          totalTested++;
          const toolCall: ToolCall = {
            tool: 'database_exec',
            params: { query: mutated },
          };
          const verdict = engine.evaluate(toolCall);
          expect(verdict.allowed).toBe(false);
          expect(verdict.violations.length).toBeGreaterThan(0);
          totalBlocked++;
        });
      }
    }

    it('verifies 100% rejection rate with zero bypasses across all generated permutations', () => {
      expect(totalBlocked).toBe(totalTested);
      expect(totalTested).toBeGreaterThan(50);
    });
  });
});
