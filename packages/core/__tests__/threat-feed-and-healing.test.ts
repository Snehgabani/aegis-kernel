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

    it('should generate suggested safe SQL mutation when query has backticks and schema', () => {
      const proposal = synthesizer.synthesizeSqlFix({
        rawQuery: 'DELETE FROM public.`users` -- evil comment',
        tenantId: 'tenant-acme-123',
        blockedReason: 'DELETE missing WHERE clause'
      });

      expect(proposal.canSelfHeal).toBe(true);
      expect(proposal.suggestedQuery).toBe("DELETE FROM public.`users` WHERE tenant_id = 'tenant-acme-123' AND id = :target_id");
    });
    
    it('should reject UPDATE with JOIN', () => {
      const proposal = synthesizer.synthesizeSqlFix({
        rawQuery: 'UPDATE users JOIN roles ON users.role_id = roles.id SET users.active = false',
        tenantId: 'tenant-acme-123',
        blockedReason: 'Complex JOIN update'
      });

      expect(proposal.canSelfHeal).toBe(false);
      expect(proposal.explanation).toContain('Complex queries such as those with JOINs');
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

    it('should persist and load from disk', () => {
      const persistPath = './tmp-threat-feed.json';
      const loader1 = new ThreatIntelligenceFeedLoader(persistPath, 30);
      loader1.ingestFeed({
        feedId: 'owasp-test',
        version: '1.0.0',
        maliciousDomains: ['evil.com']
      });
      
      const loader2 = new ThreatIntelligenceFeedLoader(persistPath, 30);
      expect(loader2.isDomainBlacklisted('evil.com')).toBe(true);
      
      // Cleanup
      require('fs').unlinkSync(persistPath);
    });
  });
});
