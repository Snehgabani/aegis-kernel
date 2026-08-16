import { describe, it, expect, beforeEach } from 'vitest';
import { AegisEngine } from '../src/engine.js';
import type { ToolCall } from '../src/types.js';

describe('Independent Audit Red-Team Verification Suite (All 25 Vectors)', () => {
  let engine: AegisEngine;

  beforeEach(() => {
    engine = new AegisEngine({
      mode: 'enforce',
      failPolicy: 'fail-closed',
      packs: ['@aegis/sql-guard', '@aegis/finance-guard', '@aegis/data-guard'],
    });
  });

  describe('P0.1 — Tool Name Gate Bypass Immunization', () => {
    it('blocks DELETE on arbitrary tool names (run_thing)', async () => {
      const call: ToolCall = { tool: 'run_thing', params: { query: 'DELETE FROM users' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks DROP TABLE on arbitrary tool names (helper)', async () => {
      const call: ToolCall = { tool: 'helper', params: { query: 'DROP TABLE users' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks DELETE on standard MCP JSON-RPC tool names (tools/call)', async () => {
      const call: ToolCall = { tool: 'tools/call', params: { query: 'DELETE FROM accounts' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks DELETE on scoped tools (postgres.execute)', async () => {
      const call: ToolCall = { tool: 'postgres.execute', params: { query: 'DELETE FROM users' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });
  });

  describe('P0.2 — Parameter Name Evasion Immunization', () => {
    it('blocks DELETE under stmt parameter name', async () => {
      const call: ToolCall = { tool: 'database_exec', params: { stmt: 'DELETE FROM users' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks DROP TABLE under body parameter name', async () => {
      const call: ToolCall = { tool: 'database_exec', params: { body: 'DROP TABLE users' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks TRUNCATE under text parameter name', async () => {
      const call: ToolCall = { tool: 'database_exec', params: { text: 'TRUNCATE users' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });
  });

  describe('P0.3 — Deep Tautology Evasion Immunization', () => {
    it('blocks DELETE with WHERE 1', async () => {
      const call: ToolCall = { tool: 'database_exec', params: { query: 'DELETE FROM users WHERE 1' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks DELETE with WHERE id > 0', async () => {
      const call: ToolCall = { tool: 'database_exec', params: { query: 'DELETE FROM users WHERE id > 0' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks DELETE with WHERE id <> -1', async () => {
      const call: ToolCall = { tool: 'database_exec', params: { query: 'DELETE FROM users WHERE id <> -1' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks DELETE with self-referential subquery WHERE id IN (SELECT id FROM users)', async () => {
      const call: ToolCall = { tool: 'database_exec', params: { query: 'DELETE FROM users WHERE id IN (SELECT id FROM users)' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });
  });

  describe('P0.4 — Numeric Field Aliasing Immunization', () => {
    it('blocks payment exceeding limit under total param', async () => {
      const call: ToolCall = { tool: 'payment', params: { total: 99999 } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks payment exceeding limit under value param', async () => {
      const call: ToolCall = { tool: 'payment', params: { value: 99999 } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks payment exceeding limit under sum param', async () => {
      const call: ToolCall = { tool: 'payment', params: { sum: 99999 } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });

    it('blocks payment exceeding limit under price param', async () => {
      const call: ToolCall = { tool: 'payment', params: { price: 99999 } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(false);
    });
  });

  describe('Utility & False Positive Preservation', () => {
    it('allows benign query with DROP in string literal', async () => {
      const call: ToolCall = { tool: 'database_exec', params: { query: "SELECT * FROM t WHERE note = 'DROP'" } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(true);
    });

    it('allows targeted DELETE with specific ID predicate', async () => {
      const call: ToolCall = { tool: 'database_exec', params: { query: 'DELETE FROM users WHERE id = 12345' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(true);
    });

    it('allows normal payment within limits', async () => {
      const call: ToolCall = { tool: 'payment', params: { total: 50.0 } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(true);
    });

    it('allows benign search queries that contain the word delete', async () => {
      const call: ToolCall = { tool: 'search_kb', params: { query: 'how to delete a user in react' } };
      const verdict = await engine.evaluate(call);
      expect(verdict.allowed).toBe(true);
    });
  });

  describe('Cryptographic Merkle Signatures & Tamper Evidence', () => {
    it('detects tampering when an attacker rewrites event log and attempts forged root without server key', async () => {
      const { computeEventChainMerkleRoot, signMerkleRoot, verifySignedChainIntegrity } = await import('../src/compliance/grc-exporter.js');
      const serverSecret = 'top-secret-signing-key-12345';
      const events = [
        {
          id: 'ev-1',
          timestamp: '2026-08-16T12:00:00Z',
          toolName: 'database_exec',
          params: { query: 'DELETE FROM users' },
          verdict: 'BLOCKED' as const,
          rulesEvaluated: 10,
          rulesFired: [],
          latencyMs: 0.8,
          proofHash: 'proof-1',
        },
      ];

      const root = computeEventChainMerkleRoot(events);
      const signature = signMerkleRoot(root, serverSecret);

      // Verify legitimate root + signature
      const legitCheck = verifySignedChainIntegrity(events, root, signature, serverSecret);
      expect(legitCheck.valid).toBe(true);
      expect(legitCheck.signatureValid).toBe(true);

      // Attacker tampers with event log (flips BLOCKED to ALLOWED)
      const tamperedEvents = [
        {
          ...events[0],
          verdict: 'ALLOWED' as const,
        },
      ];

      // If attacker recomputes root, signature verification fails
      const forgedRoot = computeEventChainMerkleRoot(tamperedEvents);
      const tamperedCheck = verifySignedChainIntegrity(tamperedEvents, forgedRoot, signature, serverSecret);
      expect(tamperedCheck.valid).toBe(false);
      expect(tamperedCheck.signatureValid).toBe(false);
    });
  });
});
