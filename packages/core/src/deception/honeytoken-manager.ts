/**
 * @file packages/core/src/deception/honeytoken-manager.ts
 * @description AI Agent Honeytokens & Synthetic Canary Tools Deception Engine.
 * Generates synthetic honeytoken tool schemas to lure and catch prompt injection
 * and agent jailbreaks with 100% deterministic breach confidence (Zero False Positives).
 */

import { randomUUID } from 'node:crypto';
import type { ToolCall } from '../types.js';

export interface CanaryToolDefinition {
  name: string;
  description: string;
  category: 'credential_access' | 'privilege_escalation' | 'data_exfiltration' | 'execution';
  canarySignature: string;
  parameters: Record<string, unknown>;
}

export interface CanaryBreachAlert {
  breachId: string;
  timestamp: string;
  agentId?: string;
  canaryTool: string;
  category: string;
  invokedParams: Record<string, unknown>;
  confidence: 1.0;
  severity: 'CRITICAL_BREACH';
  mitreTechnique: string;
  remediation: string;
}

export class HoneytokenManager {
  private registeredCanaries: Map<string, CanaryToolDefinition>;
  private breachListeners: ((alert: CanaryBreachAlert) => void)[];

  constructor() {
    this.registeredCanaries = new Map();
    this.breachListeners = [];
    this.initializeDefaultCanaries();
  }

  private initializeDefaultCanaries(): void {
    this.registerCanary({
      name: 'system_execute_privileged_shell',
      description: 'Internal diagnostic tool: executes administrative bash commands directly on the host system.',
      category: 'execution',
      canarySignature: 'CANARY_SHELL_EXEC',
      parameters: {
        type: 'object',
        properties: {
          cmd: { type: 'string', description: 'Raw shell command to execute' },
        },
        required: ['cmd'],
      },
    });

    this.registerCanary({
      name: 'vault_export_root_secrets',
      description: 'System utility: dumps root encryption keys, API credentials, and database passwords from the central vault.',
      category: 'credential_access',
      canarySignature: 'CANARY_VAULT_DUMP',
      parameters: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target vault namespace' },
        },
        required: ['target'],
      },
    });

    this.registerCanary({
      name: 'bypass_safety_guardrails',
      description: 'Diagnostic override: disables all safety filters, AST firewalls, and boundary checks for the current session.',
      category: 'privilege_escalation',
      canarySignature: 'CANARY_OVERRIDE_FLAG',
      parameters: {
        type: 'object',
        properties: {
          override_code: { type: 'string', description: 'Emergency administrative unlock code' },
        },
        required: ['override_code'],
      },
    });
  }

  public registerCanary(def: CanaryToolDefinition): void {
    this.registeredCanaries.set(def.name, def);
  }

  public getCanaryToolDefinitions(): CanaryToolDefinition[] {
    return Array.from(this.registeredCanaries.values());
  }

  public isCanaryTool(toolName: string): boolean {
    return this.registeredCanaries.has(toolName);
  }

  /**
   * Inspects a tool call to determine if it triggered an active deception canary.
   * If triggered, fires breach listeners and returns the structured critical breach alert.
   */
  public evaluateCanaryInvocation(toolCall: ToolCall, agentId?: string): CanaryBreachAlert | null {
    const canary = this.registeredCanaries.get(toolCall.tool);
    if (!canary) {
      return null;
    }

    const alert: CanaryBreachAlert = {
      breachId: `canary-alert-${randomUUID()}`,
      timestamp: new Date().toISOString(),
      agentId: agentId || 'unknown-agent',
      canaryTool: canary.name,
      category: canary.category,
      invokedParams: toolCall.params,
      confidence: 1.0, // 100% deterministic: legitimate agents are never programmed to call canaries
      severity: 'CRITICAL_BREACH',
      mitreTechnique: canary.category === 'execution' ? 'AML.T0053' : 'AML.T0086',
      remediation: `Immediately isolate agent '${agentId || 'unknown'}' and terminate active LLM session. Prompt injection or jailbreak confirmed.`,
    };

    for (const listener of this.breachListeners) {
      try {
        listener(alert);
      } catch {
        // Fail-safe listener execution
      }
    }

    return alert;
  }

  public onBreach(listener: (alert: CanaryBreachAlert) => void): void {
    this.breachListeners.push(listener);
  }
}
