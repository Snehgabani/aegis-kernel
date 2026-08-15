/**
 * @file packages/core/src/threat-feed.ts
 * @description Real-Time Threat Intelligence Feed Ingestor & Dynamic Blocklist Engine.
 */

export interface ThreatFeedPayload {
  feedId: string;
  version: string;
  maliciousDomains?: string[];
  blacklistedAgents?: string[];
  toxicKeywords?: string[];
  ipSubnets?: string[];
}

export class ThreatIntelligenceFeedLoader {
  private blacklistedDomains: Set<string> = new Set();
  private compromisedAgents: Set<string> = new Set();
  private toxicPatterns: Set<string> = new Set();
  private activeFeeds: Map<string, { version: string; updatedAt: number }> = new Map();

  /**
   * Ingests a new dynamic threat feed update in zero downtime.
   */
  public ingestFeed(feed: ThreatFeedPayload): void {
    if (feed.maliciousDomains) {
      for (const domain of feed.maliciousDomains) {
        this.blacklistedDomains.add(domain.toLowerCase().trim());
      }
    }

    if (feed.blacklistedAgents) {
      for (const agentId of feed.blacklistedAgents) {
        this.compromisedAgents.add(agentId.trim());
      }
    }

    if (feed.toxicKeywords) {
      for (const kw of feed.toxicKeywords) {
        this.toxicPatterns.add(kw.toLowerCase().trim());
      }
    }

    this.activeFeeds.set(feed.feedId, {
      version: feed.version,
      updatedAt: Date.now()
    });
  }

  /**
   * Checks if an external HTTP egress domain is on the malicious blocklist.
   */
  public isDomainBlacklisted(domain: string): boolean {
    return this.blacklistedDomains.has(domain.toLowerCase().trim());
  }

  /**
   * Checks if an agent ID has been reported as compromised or quarantined.
   */
  public isAgentCompromised(agentId: string): boolean {
    return this.compromisedAgents.has(agentId.trim());
  }

  /**
   * Scans text content for known toxic prompt injection keywords from threat feeds.
   */
  public scanForThreatKeywords(text: string): { found: boolean; keyword?: string } {
    const lower = text.toLowerCase();
    for (const kw of this.toxicPatterns) {
      if (lower.includes(kw)) {
        return { found: true, keyword: kw };
      }
    }
    return { found: false };
  }

  /**
   * Returns active threat intelligence feed metadata.
   */
  public getFeedStatus(): { activeFeeds: number; totalBlockedDomains: number; totalBlockedAgents: number } {
    return {
      activeFeeds: this.activeFeeds.size,
      totalBlockedDomains: this.blacklistedDomains.size,
      totalBlockedAgents: this.compromisedAgents.size
    };
  }
}
