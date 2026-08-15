/**
 * @file packages/core/src/threat-feed.ts
 * @description Real-Time Threat Intelligence Feed Ingestor & Dynamic Blocklist Engine.
 */

import * as fs from 'fs';

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
  private activeFeeds: Map<string, { payload: ThreatFeedPayload; updatedAt: number }> = new Map();
  private persistPath?: string;
  private maxAgeMs: number;

  constructor(persistPath?: string, maxAgeDays: number = 30) {
    this.persistPath = persistPath;
    this.maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
    if (this.persistPath) {
      this.loadFromDisk();
    }
  }

  public loadFromDisk(): void {
    if (!this.persistPath) return;
    try {
      if (fs.existsSync(this.persistPath)) {
        const data = fs.readFileSync(this.persistPath, 'utf-8');
        const parsed = JSON.parse(data);
        
        const now = Date.now();
        const activeFeedsArray = parsed.activeFeeds || [];
        
        this.blacklistedDomains.clear();
        this.compromisedAgents.clear();
        this.toxicPatterns.clear();
        this.activeFeeds.clear();
        
        for (const feed of activeFeedsArray) {
          if (now - feed.updatedAt <= this.maxAgeMs) {
            this.activeFeeds.set(feed.feedId, { payload: feed.payload, updatedAt: feed.updatedAt });
            this.applyFeed(feed.payload);
          }
        }
      }
    } catch (e) {
      console.error('Failed to load threat feed from disk:', e);
    }
  }
  
  private saveToDisk(): void {
    if (!this.persistPath) return;
    try {
      const activeFeedsArray = Array.from(this.activeFeeds.entries()).map(([feedId, data]) => ({
        feedId,
        ...data
      }));
      
      const payload = {
        activeFeeds: activeFeedsArray
      };
      
      fs.writeFileSync(this.persistPath, JSON.stringify(payload, null, 2), 'utf-8');
    } catch (e) {
      console.error('Failed to save threat feed to disk:', e);
    }
  }

  private applyFeed(feed: ThreatFeedPayload): void {
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
  }

  /**
   * Ingests a new dynamic threat feed update in zero downtime.
   */
  public ingestFeed(feed: ThreatFeedPayload): void {
    this.applyFeed(feed);

    this.activeFeeds.set(feed.feedId, {
      payload: feed,
      updatedAt: Date.now()
    });
    
    this.saveToDisk();
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
