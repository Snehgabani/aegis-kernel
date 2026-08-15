/**
 * @file packages/core/src/identity/agent-identity.ts
 * @description Non-Human Identity (NHI) & Agent Attestation Framework for Aegis Kernel.
 */

export interface AgentIdentityProfile {
  agentId: string;
  role: string;
  allowedTools: string[];
  maxTransactionLimit?: number;
  allowedSqlOperations?: ('SELECT' | 'INSERT' | 'UPDATE' | 'DELETE')[];
  allowedDomains?: string[];
  tenantId?: string;
  metadata?: Record<string, any>;
}

export interface CapabilityCheck {
  toolName: string;
  amount?: number;
  sqlOperation?: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';
  targetDomain?: string;
}

export interface CapabilityResult {
  allowed: boolean;
  reason?: string;
  profile?: AgentIdentityProfile;
}

export class AgentIdentityManager {
  private profiles: Map<string, AgentIdentityProfile> = new Map();

  /**
   * Registers or updates an Agent Non-Human Identity profile.
   */
  public registerAgent(profile: AgentIdentityProfile): void {
    this.profiles.set(profile.agentId, profile);
  }

  /**
   * Retrieves an agent profile by agentId.
   */
  public getProfile(agentId: string): AgentIdentityProfile | null {
    return this.profiles.get(agentId) ?? null;
  }

  /**
   * Validates whether an agent has authorization to perform a specific action based on its identity profile.
   */
  public validateCapability(agentId: string, check: CapabilityCheck): CapabilityResult {
    const profile = this.profiles.get(agentId);
    if (!profile) {
      // Unregistered agent defaults to permissive or strict based on policy
      return {
        allowed: false,
        reason: `Agent '${agentId}' is not registered in the Non-Human Identity (NHI) registry`
      };
    }

    // 1. Tool Permission Scope
    if (profile.allowedTools.length > 0 && !profile.allowedTools.includes(check.toolName) && !profile.allowedTools.includes('*')) {
      return {
        allowed: false,
        reason: `Tool not permitted for agent role '${profile.role}'. Allowed: [${profile.allowedTools.join(', ')}]`,
        profile
      };
    }

    // 2. Financial Transaction Bounds
    if (check.amount !== undefined && profile.maxTransactionLimit !== undefined) {
      if (check.amount > profile.maxTransactionLimit) {
        return {
          allowed: false,
          reason: `Requested transaction amount ($${check.amount}) exceeds agent role limit ($${profile.maxTransactionLimit})`,
          profile
        };
      }
    }

    // 3. SQL Operation Scope
    if (check.sqlOperation && profile.allowedSqlOperations && profile.allowedSqlOperations.length > 0) {
      if (!profile.allowedSqlOperations.includes(check.sqlOperation)) {
        return {
          allowed: false,
          reason: `SQL operation '${check.sqlOperation}' prohibited for agent role '${profile.role}'`,
          profile
        };
      }
    }

    // 4. Domain Egress Scope
    if (check.targetDomain && profile.allowedDomains && profile.allowedDomains.length > 0) {
      if (!profile.allowedDomains.includes(check.targetDomain) && !profile.allowedDomains.includes('*')) {
        return {
          allowed: false,
          reason: `External HTTP egress to '${check.targetDomain}' not allowed for agent role '${profile.role}'`,
          profile
        };
      }
    }

    return {
      allowed: true,
      profile
    };
  }
}
