export interface DelegationHop {
  fromAgent: string;
  toAgent: string;
  token: string;
  timestamp: number;
}

export interface SwarmSpendCeiling {
  totalAllowed: number;
  currentSpent: number;
}

/**
 * DelegationRouter manages multi-hop delegation across agent swarms,
 * enforcing global swarm invariants (e.g. cumulative spend ceilings, depth limits).
 */
export class DelegationRouter {
  private activeDelegations: Map<string, DelegationHop[]> = new Map();
  private swarmCeilings: Map<string, SwarmSpendCeiling> = new Map();
  private maxDelegationDepth: number;

  constructor(maxDelegationDepth: number = 5) {
    this.maxDelegationDepth = maxDelegationDepth;
  }

  public registerSwarmCeiling(swarmId: string, totalAllowed: number): void {
    this.swarmCeilings.set(swarmId, { totalAllowed, currentSpent: 0 });
  }

  public recordHop(
    swarmId: string,
    fromAgent: string,
    toAgent: string,
    token: string
  ): { allowed: boolean; reason?: string; depth: number } {
    const history = this.activeDelegations.get(swarmId) || [];

    // 1. Check Delegation Depth
    if (history.length >= this.maxDelegationDepth) {
      return { allowed: false, reason: `Max delegation depth (${this.maxDelegationDepth}) exceeded`, depth: history.length };
    }

    // 2. Check Circular Delegation Loop
    const visited = new Set(history.map(h => h.fromAgent));
    if (visited.has(toAgent)) {
      return { allowed: false, reason: `Circular delegation detected: agent ${toAgent} already in chain`, depth: history.length };
    }

    history.push({ fromAgent, toAgent, token, timestamp: Date.now() });
    this.activeDelegations.set(swarmId, history);

    return { allowed: true, depth: history.length };
  }

  public recordSpend(swarmId: string, amount: number): { allowed: boolean; remainingBudget: number; reason?: string } {
    const ceiling = this.swarmCeilings.get(swarmId);
    if (!ceiling) {
      // If no explicit ceiling, default allow
      return { allowed: true, remainingBudget: Infinity };
    }

    if (ceiling.currentSpent + amount > ceiling.totalAllowed) {
      return {
        allowed: false,
        remainingBudget: ceiling.totalAllowed - ceiling.currentSpent,
        reason: `Global swarm budget ($${ceiling.totalAllowed}) exceeded by attempted spend of $${amount}`,
      };
    }

    ceiling.currentSpent += amount;
    return {
      allowed: true,
      remainingBudget: ceiling.totalAllowed - ceiling.currentSpent,
    };
  }

  public getSwarmDepth(swarmId: string): number {
    return this.activeDelegations.get(swarmId)?.length || 0;
  }
}
