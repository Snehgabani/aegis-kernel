/**
 * @file packages/core/src/quarantine/distributed-circuit-breaker.ts
 * @description Distributed Circuit Breaker & Agent Quarantine for Multi-Node Fleets.
 * Synchronizes strikes, sliding window violations, and quarantine states across distributed
 * agent clusters (Kubernetes, AWS ECS, Celery, BullMQ) via pluggable storage adapter.
 */

export interface DistributedStorageAdapter {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;
  incr(key: string, ttlSeconds?: number): Promise<number>;
  del(key: string): Promise<void>;
}

export class InMemoryStorageAdapter implements DistributedStorageAdapter {
  private store = new Map<string, { value: string; expiresAt?: number }>();

  public async get(key: string): Promise<string | null> {
    const item = this.store.get(key);
    if (!item) return null;
    if (item.expiresAt && Date.now() > item.expiresAt) {
      this.store.delete(key);
      return null;
    }
    return item.value;
  }

  public async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    const expiresAt = ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined;
    this.store.set(key, { value, expiresAt });
  }

  public async incr(key: string, ttlSeconds?: number): Promise<number> {
    const current = await this.get(key);
    const num = (current ? parseInt(current, 10) : 0) + 1;
    await this.set(key, String(num), ttlSeconds);
    return num;
  }

  public async del(key: string): Promise<void> {
    this.store.delete(key);
  }
}

export interface DistributedCircuitBreakerOptions {
  maxStrikes?: number;
  windowSeconds?: number;
  quarantineDurationSeconds?: number;
  storage?: DistributedStorageAdapter;
  keyPrefix?: string;
}

export class DistributedCircuitBreaker {
  private maxStrikes: number;
  private windowSeconds: number;
  private quarantineDurationSeconds: number;
  private storage: DistributedStorageAdapter;
  private keyPrefix: string;

  constructor(options: DistributedCircuitBreakerOptions = {}) {
    this.maxStrikes = options.maxStrikes ?? 3;
    this.windowSeconds = options.windowSeconds ?? 60;
    this.quarantineDurationSeconds = options.quarantineDurationSeconds ?? 3600; // 1 hour default
    this.storage = options.storage ?? new InMemoryStorageAdapter();
    this.keyPrefix = options.keyPrefix ?? 'aegis:breaker';
  }

  private getStrikeKey(agentId: string): string {
    return `${this.keyPrefix}:strikes:${agentId}`;
  }

  private getQuarantineKey(agentId: string): string {
    return `${this.keyPrefix}:quarantined:${agentId}`;
  }

  /**
   * Checks if an agent is currently quarantined across the distributed cluster.
   */
  public async isQuarantined(agentId: string): Promise<boolean> {
    const res = await this.storage.get(this.getQuarantineKey(agentId));
    return res !== null;
  }

  /**
   * Records a security strike against an agent. If threshold is reached, agent is placed in quarantine.
   */
  public async recordStrike(
    agentId: string,
    reason: string
  ): Promise<{ strikes: number; quarantined: boolean; remainingStrikes: number }> {
    if (await this.isQuarantined(agentId)) {
      return { strikes: this.maxStrikes, quarantined: true, remainingStrikes: 0 };
    }

    const strikeCount = await this.storage.incr(this.getStrikeKey(agentId), this.windowSeconds);

    if (strikeCount >= this.maxStrikes) {
      await this.quarantineAgent(agentId, `Exceeded maximum strikes (${strikeCount}/${this.maxStrikes}). Last reason: ${reason}`);
      return { strikes: strikeCount, quarantined: true, remainingStrikes: 0 };
    }

    return {
      strikes: strikeCount,
      quarantined: false,
      remainingStrikes: Math.max(0, this.maxStrikes - strikeCount),
    };
  }

  /**
   * Manually quarantines an agent across the cluster.
   */
  public async quarantineAgent(agentId: string, reason: string): Promise<void> {
    const payload = JSON.stringify({
      agentId,
      quarantinedAt: new Date().toISOString(),
      reason,
    });
    await this.storage.set(this.getQuarantineKey(agentId), payload, this.quarantineDurationSeconds);
  }

  /**
   * Lifts quarantine for an agent.
   */
  public async releaseAgent(agentId: string): Promise<void> {
    await this.storage.del(this.getQuarantineKey(agentId));
    await this.storage.del(this.getStrikeKey(agentId));
  }
}
