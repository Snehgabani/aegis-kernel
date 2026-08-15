import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ReaskHandler } from '../src/auto-heal/reask-handler.js';
import { AegisEngine } from '../src/engine.js';
import { ToolCall, AegisVerdict } from '../src/types.js';

describe('ReaskHandler', () => {
  let engine: AegisEngine;
  let handler: ReaskHandler;

  beforeEach(() => {
    engine = new AegisEngine();
    handler = new ReaskHandler(engine);
  });

  it('should return immediately if first attempt is allowed', async () => {
    vi.spyOn(engine, 'evaluateAsync').mockResolvedValue({
      allowed: true,
      violations: [],
      proofHash: 'hash',
      latencyMs: 1,
      mode: 'enforce'
    });

    const toolCall = { tool: 'test', params: {} };
    const reaskCallback = vi.fn();

    const result = await handler.evaluateWithReask(toolCall, reaskCallback);

    expect(result.attempts).toBe(1);
    expect(result.healed).toBe(false);
    expect(result.verdict.allowed).toBe(true);
    expect(reaskCallback).not.toHaveBeenCalled();
  });

  it('should heal on 2nd attempt', async () => {
    const verdictBlocked: AegisVerdict = {
      allowed: false,
      violations: [{ ruleId: 'R1', packId: 'P1', severity: 'critical', message: 'blocked' }],
      proofHash: 'hash1',
      latencyMs: 1,
      mode: 'enforce'
    };
    
    const verdictAllowed: AegisVerdict = {
      allowed: true,
      violations: [],
      proofHash: 'hash2',
      latencyMs: 1,
      mode: 'enforce'
    };

    let attempt = 0;
    vi.spyOn(engine, 'evaluateAsync').mockImplementation(async () => {
      attempt++;
      return attempt === 1 ? verdictBlocked : verdictAllowed;
    });

    const toolCall = { tool: 'test', params: { v: 1 } };
    const healedToolCall = { tool: 'test', params: { v: 2 } };
    
    const reaskCallback = vi.fn().mockResolvedValue(healedToolCall);

    const result = await handler.evaluateWithReask(toolCall, reaskCallback, undefined, { backoffMs: 1 });

    expect(result.attempts).toBe(2);
    expect(result.healed).toBe(true);
    expect(result.verdict.allowed).toBe(true);
    expect(reaskCallback).toHaveBeenCalledTimes(1);
  });

  it('should stop after max retries', async () => {
    const verdictBlocked: AegisVerdict = {
      allowed: false,
      violations: [{ ruleId: 'R1', packId: 'P1', severity: 'critical', message: 'blocked' }],
      proofHash: 'hash1',
      latencyMs: 1,
      mode: 'enforce'
    };

    vi.spyOn(engine, 'evaluateAsync').mockResolvedValue(verdictBlocked);

    const toolCall = { tool: 'test', params: {} };
    const reaskCallback = vi.fn().mockResolvedValue(toolCall);

    const result = await handler.evaluateWithReask(toolCall, reaskCallback, undefined, { maxRetries: 2, backoffMs: 1 });

    expect(result.attempts).toBe(3); // Initial + 2 retries
    expect(result.healed).toBe(false);
    expect(result.verdict.allowed).toBe(false);
    expect(reaskCallback).toHaveBeenCalledTimes(2);
  });

  it('should handle callback error', async () => {
    const verdictBlocked: AegisVerdict = {
      allowed: false,
      violations: [{ ruleId: 'R1', packId: 'P1', severity: 'critical', message: 'blocked' }],
      proofHash: 'hash1',
      latencyMs: 1,
      mode: 'enforce'
    };

    vi.spyOn(engine, 'evaluateAsync').mockResolvedValue(verdictBlocked);

    const toolCall = { tool: 'test', params: {} };
    const reaskCallback = vi.fn().mockRejectedValue(new Error('Callback failed'));

    const result = await handler.evaluateWithReask(toolCall, reaskCallback, undefined, { maxRetries: 2, backoffMs: 1 });

    expect(result.attempts).toBe(1);
    expect(result.healed).toBe(false);
    expect(result.verdict.allowed).toBe(false);
    expect(reaskCallback).toHaveBeenCalledTimes(1);
  });
  
  it('should handle empty violations', async () => {
    const verdictBlocked: AegisVerdict = {
      allowed: false,
      violations: [],
      proofHash: 'hash1',
      latencyMs: 1,
      mode: 'enforce'
    };

    vi.spyOn(engine, 'evaluateAsync').mockResolvedValue(verdictBlocked);

    const toolCall = { tool: 'test', params: {} };
    const reaskCallback = vi.fn().mockRejectedValue(new Error('Stop'));

    const result = await handler.evaluateWithReask(toolCall, reaskCallback, undefined, { maxRetries: 1, backoffMs: 1 });
    
    // Checking history to see corrective prompt output for empty violations
    expect(result.history[0].correctivePrompt).toContain('Unknown violation');
  });
});
