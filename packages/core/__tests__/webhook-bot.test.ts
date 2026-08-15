import { describe, it, expect, vi } from 'vitest';
import { AegisWebhookBot } from '../src/telemetry/webhook-bot.js';
import type { AegisEvent } from '../src/types.js';

describe('AegisWebhookBot Notification & Alerting', () => {
  it('should filter alerts based on configured minimum severity', () => {
    const bot = new AegisWebhookBot({ minSeverity: 'critical' });

    const lowEvent: AegisEvent = {
      id: 'event-1',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      framework: 'mcp',
      toolName: 'read_doc',
      toolCallFingerprint: 'fp-1',
      mode: 'enforce',
      verdict: 'BLOCKED',
      rulesEvaluated: 1,
      rulesFired: [
        {
          ruleId: 'info-rule',
          packId: 'test-pack',
          severity: 'info',
          message: 'Minor info notice'
        }
      ],
      latencyMs: 0.2,
      proofHash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      policyCommitmentHash: 'pol-1',
      userOverride: false
    };

    const criticalEvent: AegisEvent = {
      ...lowEvent,
      rulesFired: [
        {
          ruleId: 'sql-block-drop',
          packId: '@aegis/sql-guard',
          severity: 'critical',
          message: 'Blocked mass DROP TABLE'
        }
      ]
    };

    const allowedEvent: AegisEvent = {
      ...criticalEvent,
      verdict: 'ALLOWED'
    };

    expect(bot.shouldAlert(lowEvent)).toBe(false);
    expect(bot.shouldAlert(criticalEvent)).toBe(true);
    expect(bot.shouldAlert(allowedEvent)).toBe(false);
  });

  it('should format and dispatch mock alert payloads without throwing', async () => {
    const bot = new AegisWebhookBot({
      minSeverity: 'warning',
      slackWebhookUrl: 'https://hooks.slack.com/services/TEST/MOCK/123',
      discordWebhookUrl: 'https://discord.com/api/webhooks/TEST/MOCK'
    });

    const event: AegisEvent = {
      id: 'event-2',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      framework: 'openai',
      toolName: 'execute_payout',
      toolCallFingerprint: 'fp-2',
      mode: 'enforce',
      verdict: 'BLOCKED',
      rulesEvaluated: 3,
      rulesFired: [
        {
          ruleId: 'fin-single-limit',
          packId: '@aegis/finance-guard',
          severity: 'critical',
          message: 'Transfer amount $500,000 exceeds single-transaction ceiling of $10,000'
        }
      ],
      latencyMs: 0.35,
      proofHash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      policyCommitmentHash: 'pol-2',
      userOverride: false
    };

    const originalFetch = global.fetch;
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });

    const result = await bot.dispatchAlert(event);
    expect(result.slack).toBe(true);
    expect(result.discord).toBe(true);

    global.fetch = originalFetch;
  });
});
