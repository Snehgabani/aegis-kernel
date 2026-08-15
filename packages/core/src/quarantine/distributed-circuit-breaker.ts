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
  evalScript(script: string, keys: string[], args: string[]): Promise<any>;
}

export class InMemoryStorageAdapter implements DistributedStorageAdapter {
  private store = new Map<string, { value: string; expiresAt?: number }>();
  private active = false;

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

  public async evalScript(_script: string, keys: string[], args: string[]): Promise<any> {
    while (this.active) {
      await new Promise(resolve => setTimeout(resolve, 0));
    }
    this.active = true;
    try {
      const qKey = keys[0];
      const sKey = keys[1];
      const maxStrikes = parseInt(args[0], 10);
      const window = parseInt(args[1], 10);
      const qDuration = parseInt(args[2], 10);
      const reasonPayload = args[3];

      const qVal = await this.get(qKey);
      if (qVal) {
        return [maxStrikes, 1, 0];
      }

      const strikes = await this.incr(sKey, window);
      if (strikes >= maxStrikes) {
        await this.set(qKey, reasonPayload, qDuration);
        return [strikes, 1, 0];
      }
      return [strikes, 0, maxStrikes - strikes];
    } finally {
      this.active = false;
    }
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
    const qKey = this.getQuarantineKey(agentId);
    const sKey = this.getStrikeKey(agentId);

    const payload = JSON.stringify({
      agentId,
      quarantinedAt: new Date().toISOString(),
      reason: `Exceeded maximum strikes. Last reason: ${reason}`,
    });

    const script = `
      local q_key = KEYS[1]
      local s_key = KEYS[2]
      local max_strikes = tonumber(ARGV[1])
      local window = tonumber(ARGV[2])
      local q_duration = tonumber(ARGV[3])
      local payload = ARGV[4]

      if redis.call('GET', q_key) then
        return {max_strikes, 1, 0}
      end

      local strikes = redis.call('INCR', s_key)
      if strikes == 1 then
        redis.call('EXPIRE', s_key, window)
      end

      if strikes >= max_strikes then
        redis.call('SETEX', q_key, q_duration, payload)
        return {strikes, 1, 0}
      end

      return {strikes, 0, max_strikes - strikes}
    `;

    const result = await this.storage.evalScript(script, [qKey, sKey], [
      String(this.maxStrikes),
      String(this.windowSeconds),
      String(this.quarantineDurationSeconds),
      payload
    ]);

    return {
      strikes: Number(result[0]),
      quarantined: Boolean(result[1]),
      remainingStrikes: Number(result[2])
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
