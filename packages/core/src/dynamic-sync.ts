import { AegisEngine } from './engine.js';
import { RulePackLoader } from './rule-loader.js';
import type { RulePack } from './types.js';


export interface DynamicSyncOptions {
  engine: AegisEngine;
  pollIntervalMs?: number;
  fetchPacksFn?: () => Promise<RulePack[]>;
}

export class AegisDynamicSyncManager {
  private engine: AegisEngine;
  private fetchPacksFn?: () => Promise<RulePack[]>;
  private pollIntervalMs: number;
  private intervalTimer: NodeJS.Timeout | null = null;
  private lastCommitmentHash: string = '';

  constructor(options: DynamicSyncOptions) {
    this.engine = options.engine;
    this.fetchPacksFn = options.fetchPacksFn;
    this.pollIntervalMs = options.pollIntervalMs || 60000;
  }

  /**
   * Atomically reloads and hot-swaps active rules on the running engine
   */
  public hotSwapRules(newPacks: RulePack[]): { applied: boolean; ruleCount: number; policyHash: string } {
    const validPacks: RulePack[] = [];
    let ruleCount = 0;

    for (const pack of newPacks) {
      if (RulePackLoader.validatePack(pack)) {
        validPacks.push(pack);
        ruleCount += pack.rules.length;
      }
    }

    if (validPacks.length === 0) {
      return { applied: false, ruleCount: 0, policyHash: this.engine.getPolicyCommitmentHash() };
    }

    // Atomic update
    this.engine.updatePacks(validPacks);
    this.lastCommitmentHash = this.engine.getPolicyCommitmentHash();

    return {
      applied: true,
      ruleCount,
      policyHash: this.lastCommitmentHash,
    };
  }

  /**
   * Triggers an immediate remote sync cycle
   */
  public async syncNow(): Promise<{ success: boolean; ruleCount?: number; error?: string }> {
    if (!this.fetchPacksFn) {
      return { success: false, error: 'No fetchPacksFn provided' };
    }

    try {
      const packs = await this.fetchPacksFn();
      const res = this.hotSwapRules(packs);
      return { success: res.applied, ruleCount: res.ruleCount };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Starts periodic polling in background
   */
  public start(): void {
    if (this.intervalTimer || !this.fetchPacksFn) return;
    this.intervalTimer = setInterval(() => {
      this.syncNow().catch(() => {});
    }, this.pollIntervalMs);
  }

  /**
   * Stops background polling
   */
  public stop(): void {
    if (this.intervalTimer) {
      clearInterval(this.intervalTimer);
      this.intervalTimer = null;
    }
  }
}
