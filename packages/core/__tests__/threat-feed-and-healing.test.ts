import { describe, it, expect } from 'vitest';
import { SelfHealingProposalSynthesizer } from '../src/self-healing';
import { ThreatIntelligenceFeedLoader } from '../src/threat-feed';

describe('Aegis Self-Healing & Threat Intelligence Feed Suite', () => {
  describe('Self-Healing Proposal Synthesizer', () => {
    const synthesizer = new SelfHealingProposalSynthesizer();

    it('should generate suggested safe SQL mutation when query lacks WHERE clause', () => {
      const proposal = synthesizer.synthesizeSqlFix({
        rawQuery: 'DELETE FROM users',
        tenantId: 'tenant-acme-123',
        blockedReason: 'DELETE missing WHERE clause (unconditional deletion)'
      });

      expect(proposal.canSelfHeal).toBe(true);
      expect(proposal.suggestedQuery).toContain('WHERE');
      expect(proposal.explanation).toBeDefined();
    });

    it('should suggest financial parameter clamp when amount exceeds authorized limit', () => {
      const proposal = synthesizer.synthesizeNumericFix({
        originalAmount: 15000,
        maxAllowed: 5000,
        currency: 'USD'
      });

      expect(proposal.canSelfHeal).toBe(true);
      expect(proposal.suggestedAmount).toBe(5000);
      expect(proposal.explanation).toContain('Clamped to maximum authorized threshold');
    });
  });

  describe('Threat Intelligence Feed Loader', () => {
    const loader = new ThreatIntelligenceFeedLoader();

    it('should ingest external threat feed and block malicious domains in real time', () => {
      loader.ingestFeed({
        feedId: 'owasp-agent-blocklist-2026',
        version: '1.2.0',
        maliciousDomains: ['evil-agent-c2.com', 'exfil-gateway.io'],
        blacklistedAgents: ['compromised-bot-77'],
        toxicKeywords: ['system-override-token-99']
      });

      expect(loader.isDomainBlacklisted('evil-agent-c2.com')).toBe(true);
      expect(loader.isDomainBlacklisted('api.stripe.com')).toBe(false);

      expect(loader.isAgentCompromised('compromised-bot-77')).toBe(true);
      expect(loader.isAgentCompromised('legitimate-worker-01')).toBe(false);
    });
  });
});
