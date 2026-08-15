/**
 * Aegis Security Alert Webhook Bot
 * Dispatches real-time incident notifications to Slack and Discord upon invariant violations.
 * 
 * @remarks This module performs network egress when explicitly enabled. The core engine never enables this by default.
 */

import type { AegisEvent, AegisSeverity } from '../types.js';

export interface WebhookBotConfig {
  slackWebhookUrl?: string;
  discordWebhookUrl?: string;
  minSeverity?: AegisSeverity;
  enabled?: boolean;
}

export class AegisWebhookBot {
  private config: WebhookBotConfig;

  constructor(config: WebhookBotConfig = {}) {
    this.config = {
      enabled: config.enabled ?? false,
      minSeverity: config.minSeverity ?? 'critical',
      slackWebhookUrl: config.slackWebhookUrl || process.env.AEGIS_SLACK_WEBHOOK_URL,
      discordWebhookUrl: config.discordWebhookUrl || process.env.AEGIS_DISCORD_WEBHOOK_URL
    };
  }

  /**
   * Evaluates whether an audit event should trigger an alert.
   */
  public shouldAlert(event: AegisEvent): boolean {
    if (!this.config.enabled || event.verdict === 'ALLOWED' || !event.rulesFired || event.rulesFired.length === 0) {
      return false;
    }
    const severityRanks: Record<string, number> = {
      info: 1,
      warning: 2,
      critical: 3
    };
    const minRank = severityRanks[this.config.minSeverity || 'critical'] || 3;
    
    // Find highest severity in rulesFired
    const maxEventRank = Math.max(...event.rulesFired.map(r => severityRanks[r.severity] || 1));
    return maxEventRank >= minRank;
  }

  /**
   * Dispatches formatted alert to configured channels.
   */
  public async dispatchAlert(event: AegisEvent): Promise<{ slack: boolean; discord: boolean }> {
    if (!this.shouldAlert(event)) {
      return { slack: false, discord: false };
    }

    const results = { slack: false, discord: false };
    const violationMessages = event.rulesFired.map(r => `• [${r.severity.toUpperCase()}] ${r.message}`).join('\n');

    if (this.config.slackWebhookUrl) {
      try {
        const payload = {
          text: `🚨 *[Aegis Security Alert]* AI Agent Tool Invariant Blocked!`,
          blocks: [
            {
              type: 'section',
              text: {
                type: 'mrkdwn',
                text: `🚨 *[Aegis Security Alert]* Tool Action Blocked!\n*Tool:* \`${event.toolName}\` | *Framework:* \`${event.framework}\``
              }
            },
            {
              type: 'section',
              fields: [
                { type: 'mrkdwn', text: `*Violations:*\n${violationMessages}` },
                { type: 'mrkdwn', text: `*Proof Hash:*\n\`${event.proofHash.substring(0, 16)}...\`` }
              ]
            }
          ]
        };
        await fetch(this.config.slackWebhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        results.slack = true;
      } catch {
        results.slack = false;
      }
    }

    if (this.config.discordWebhookUrl) {
      try {
        const payload = {
          content: `🚨 **[Aegis Security Alert]** Invariant Violation Blocked!`,
          embeds: [
            {
              title: `Blocked Action on Tool: ${event.toolName}`,
              color: 0xff0000,
              fields: [
                { name: 'Proof Hash', value: `\`${event.proofHash.substring(0, 16)}...\``, inline: true },
                { name: 'Violations', value: violationMessages || 'None' }
              ],
              timestamp: new Date().toISOString()
            }
          ]
        };
        await fetch(this.config.discordWebhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        results.discord = true;
      } catch {
        results.discord = false;
      }
    }

    return results;
  }
}
