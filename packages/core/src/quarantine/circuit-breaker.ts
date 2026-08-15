/**
 * @file packages/core/src/quarantine/circuit-breaker.ts
 * @description Automated Security Quarantine & Adaptive Circuit Breaker for Rogue AI Agents.
 */

export interface CircuitBreakerConfig {
  maxStrikes?: number;
  windowSeconds?: number;
  quarantineDurationSeconds?: number;
}

export interface SecurityStrike {
  timestamp: number;
  reason: string;
  metadata?: Record<string, any>;
}

export interface AgentQuarantineStatus {
  agentId: string;
  state: 'NORMAL' | 'WARNED' | 'QUARANTINED';
  strikeCount: number;
  quarantinedAt?: number;
  quarantineExpiresAt?: number;
  quarantineReason?: string;
}

export class AgentCircuitBreaker {
  private strikes: Map<string, SecurityStrike[]> = new Map();
  private quarantines: Map<string, { quarantinedAt: number; expiresAt: number; reason: string }> = new Map();
  private maxStrikes: number;
  private windowMs: number;
  private quarantineDurationMs: number;

  constructor(config: CircuitBreakerConfig = {}) {
    this.maxStrikes = config.maxStrikes ?? 3;
    this.windowMs = (config.windowSeconds ?? 60) * 1000;
    this.quarantineDurationMs = (config.quarantineDurationSeconds ?? 300) * 1000; // 5 minutes default
  }

  /**
   * Checks if an agent is currently quarantined.
   */
  public isQuarantined(agentId: string): boolean {
    const record = this.quarantines.get(agentId);
    if (!record) return false;

    if (Date.now() > record.expiresAt) {
      this.quarantines.delete(agentId);
      return false;
    }

    return true;
  }

  /**
   * Records a security violation strike against an agent.
   * Trips the circuit breaker and quarantines the agent if strikes exceed threshold.
   */
  public recordStrike(
    agentId: string,
    reason: string,
    metadata?: Record<string, any>
  ): { quarantined: boolean; currentStrikes: number; message: string } {
    const now = Date.now();
    const agentStrikes = this.strikes.get(agentId) ?? [];

    // Filter out strikes older than sliding window
    const recentStrikes = agentStrikes.filter(s => now - s.timestamp <= this.windowMs);
    recentStrikes.push({ timestamp: now, reason, metadata });
    this.strikes.set(agentId, recentStrikes);

    if (recentStrikes.length >= this.maxStrikes) {
      const expiresAt = now + this.quarantineDurationMs;
      const quarantineReason = `Exceeded ${this.maxStrikes} security strikes in ${this.windowMs / 1000}s. Last violation: ${reason}`;

      this.quarantines.set(agentId, {
        quarantinedAt: now,
        expiresAt,
        reason: quarantineReason
      });

      return {
        quarantined: true,
        currentStrikes: recentStrikes.length,
        message: `🚨 Agent '${agentId}' has been quarantined for ${this.quarantineDurationMs / 1000}s: ${quarantineReason}`
      };
    }

    return {
      quarantined: false,
      currentStrikes: recentStrikes.length,
      message: `⚠️ Security strike recorded for agent '${agentId}' (${recentStrikes.length}/${this.maxStrikes})`
    };
  }

  private auditLog: { timestamp: number; agentId: string; action: string; admin: string }[] = [];

  /**
   * Manually lifts quarantine for an agent (e.g. by security administrator).
   */
  public liftQuarantine(agentId: string, adminIdentity = 'system'): boolean {
    if (this.quarantines.has(agentId)) {
      this.quarantines.delete(agentId);
      this.strikes.delete(agentId);
      this.auditLog.push({ timestamp: Date.now(), agentId, action: 'LIFT_QUARANTINE', admin: adminIdentity });
      return true;
    }
    return false;
  }

  /**
   * Retrieves complete status and strike history for an agent.
   */
  public getAgentStatus(agentId: string): AgentQuarantineStatus {
    const isQ = this.isQuarantined(agentId);
    const qRecord = this.quarantines.get(agentId);
    const agentStrikes = this.strikes.get(agentId) ?? [];
    const now = Date.now();
    const activeStrikes = agentStrikes.filter(s => now - s.timestamp <= this.windowMs);

    return {
      agentId,
      state: isQ ? 'QUARANTINED' : activeStrikes.length > 0 ? 'WARNED' : 'NORMAL',
      strikeCount: activeStrikes.length,
      quarantinedAt: qRecord?.quarantinedAt,
      quarantineExpiresAt: qRecord?.expiresAt,
      quarantineReason: qRecord?.reason
    };
  }
}
