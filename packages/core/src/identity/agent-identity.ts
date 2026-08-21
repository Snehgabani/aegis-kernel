/**
 * @file packages/core/src/identity/agent-identity.ts
 * @description Non-Human Identity (NHI) & Agent Attestation Framework for Aegis Kernel,
 * incorporating Google DeepMind CaMeL Dual-State ($P\text{-LLM}$ / $Q\text{-LLM}$) context separation.
 */

export type AgentExecutionRole = 'privileged_planner' | 'quarantined_worker' | 'standard_executor';

export interface AgentIdentityProfile {
  agentId: string;
  role: string;
  allowedTools: string[];
  executionRole?: AgentExecutionRole;
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
  isMutatingAction?: boolean;
}

export interface CapabilityResult {
  allowed: boolean;
  reason?: string;
  profile?: AgentIdentityProfile;
}

const DEFAULT_MUTATING_TOOLS = new Set([
  'database_exec',
  'execute_sql',
  'filesystem_write',
  'execute_bash',
  'wire_transfer',
  'delete_file',
  'drop_database',
  'send_email',
  'webhook_dispatch',
]);

export class AgentIdentityManager {
  private profiles: Map<string, AgentIdentityProfile> = new Map();

  /**
   * Registers or updates an Agent Non-Human Identity profile.
   */
  public registerAgent(profile: AgentIdentityProfile): void {
    const normalized: AgentIdentityProfile = {
      ...profile,
      executionRole: profile.executionRole ?? 'standard_executor',
    };
    this.profiles.set(profile.agentId, normalized);
  }

  /**
   * Retrieves an agent profile by agentId.
   */
  public getProfile(agentId: string): AgentIdentityProfile | null {
    return this.profiles.get(agentId) ?? null;
  }

  /**
   * Dynamically quarantines an agent (Google DeepMind CaMeL pattern) when untrusted input is ingested.
   */
  public quarantineAgent(agentId: string, reason = 'Untrusted payload ingested'): void {
    const profile = this.profiles.get(agentId);
    if (profile) {
      profile.executionRole = 'quarantined_worker';
      profile.metadata = {
        ...(profile.metadata ?? {}),
        quarantinedAt: new Date().toISOString(),
        quarantineReason: reason,
      };
    }
  }

  /**
   * Restores an agent to privileged planner status.
   */
  public restoreAgent(agentId: string): void {
    const profile = this.profiles.get(agentId);
    if (profile) {
      profile.executionRole = 'privileged_planner';
    }
  }

  /**
   * Validates whether an agent has authorization to perform a specific action based on its identity profile.
   */
  public validateCapability(agentId: string, check: CapabilityCheck): CapabilityResult {
    const profile = this.profiles.get(agentId);
    if (!profile) {
      return {
        allowed: false,
        reason: `Agent '${agentId}' is not registered in the Non-Human Identity (NHI) registry`,
      };
    }

    // 1. Google DeepMind CaMeL Dual-State Machine Invariant
    if (profile.executionRole === 'quarantined_worker') {
      const isMutating =
        check.isMutatingAction ||
        DEFAULT_MUTATING_TOOLS.has(check.toolName) ||
        check.toolName.startsWith('delete_') ||
        check.toolName.startsWith('drop_');

      if (isMutating) {
        return {
          allowed: false,
          reason: `CaMeL Invariant: Quarantined worker agent '${agentId}' is forbidden from invoking mutating tool '${check.toolName}'`,
          profile,
        };
      }
    }

    // 2. Tool Permission Scope
    if (
      profile.allowedTools.length > 0 &&
      !profile.allowedTools.includes(check.toolName) &&
      !profile.allowedTools.includes('*')
    ) {
      return {
        allowed: false,
        reason: `Tool not permitted for agent role '${profile.role}'. Allowed: [${profile.allowedTools.join(', ')}]`,
        profile,
      };
    }

    // 3. Financial Transaction Bounds
    if (check.amount !== undefined && profile.maxTransactionLimit !== undefined) {
      if (check.amount > profile.maxTransactionLimit) {
        return {
          allowed: false,
          reason: `Requested transaction amount ($${check.amount}) exceeds agent role limit ($${profile.maxTransactionLimit})`,
          profile,
        };
      }
    }

    // 4. SQL Operation Scope
    if (check.sqlOperation && profile.allowedSqlOperations && profile.allowedSqlOperations.length > 0) {
      if (!profile.allowedSqlOperations.includes(check.sqlOperation)) {
        return {
          allowed: false,
          reason: `SQL operation '${check.sqlOperation}' prohibited for agent role '${profile.role}'`,
          profile,
        };
      }
    }

    // 5. Domain Egress Scope
    if (check.targetDomain && profile.allowedDomains && profile.allowedDomains.length > 0) {
      if (!profile.allowedDomains.includes(check.targetDomain) && !profile.allowedDomains.includes('*')) {
        return {
          allowed: false,
          reason: `External HTTP egress to '${check.targetDomain}' not allowed for agent role '${profile.role}'`,
          profile,
        };
      }
    }

    return {
      allowed: true,
      profile,
    };
  }
}
