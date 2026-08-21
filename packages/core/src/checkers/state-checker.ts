import type { AegisViolation, EvaluationScratch, ToolCall } from '../types.js';
import { CustomChecker } from './custom-checker.js';

export interface StateInvariantConditionParams {
  target_field?: string; // Optional field on toolCall.params (e.g. 'amount')
  tenant_field?: string; // Optional tenant/account isolation field (e.g. 'organizationId' or 'tenantId')
  require_state?: boolean; // If true, strictly fails when stateContext is omitted
  precondition?: string; // Must be true before action can proceed (e.g. "state.account_status == 'active'")
  assertion: string; // Invariant that must hold across transition (e.g. "state.spent_today + params.amount <= state.daily_budget")
}

export interface StateInvariantCondition {
  type: 'state_invariant';
  params: StateInvariantConditionParams;
}

export class StateChecker {
  private dslEvaluator: CustomChecker;

  constructor() {
    this.dslEvaluator = new CustomChecker();
  }

  public evaluate(
    ruleId: string,
    packId: string,
    params: StateInvariantConditionParams,
    toolCall: ToolCall,
    stateContext?: Record<string, unknown>,
    severity: import("../types.js").AegisSeverity = "critical",
    scratch?: EvaluationScratch
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];

    // If this state rule targets a specific field (e.g. 'amount') and the tool
    // call doesn't have it, skip. The nested tree walk is memoized per
    // evaluate() call so repeated probes across state rules short-circuit.
    if (params.target_field && !(params.target_field in toolCall.params)) {
      const probed = scratch?.stateProbed.get(toolCall.params);
      if (probed?.has(params.target_field)) {
        return violations;
      }
      const found = this.findNestedValue(toolCall.params, params.target_field);
      if (found === undefined) {
        if (scratch) {
          let set = scratch.stateProbed.get(toolCall.params);
          if (!set) {
            set = new Set<string>();
            scratch.stateProbed.set(toolCall.params, set);
          }
          set.add(params.target_field);
        }
        return violations;
      }
    }

    // Tenant isolation verification: parameters must match the authenticated tenant in state
    if (params.tenant_field) {
      const toolTenant = toolCall.params[params.tenant_field] ?? this.findNestedTenant(toolCall.params, params.tenant_field);
      // If neither toolCall nor state specifies this tenant_field, skip tenant isolation check
      if (toolTenant === undefined && (!stateContext || !(params.tenant_field in stateContext))) {
        return violations;
      }
      if (stateContext) {
        const stateTenant = (stateContext as any)[params.tenant_field];
        if (toolTenant !== undefined && stateTenant !== undefined && toolTenant !== stateTenant) {
          violations.push({
            ruleId,
            packId,
            severity,
            message: `Cross-tenant isolation violation: Tool requested tenant '${toolTenant}' does not match authenticated session tenant '${stateTenant}'.`,
            suggestedFix: `Restrict tool call parameters to the caller's active tenant '${stateTenant}'.`,
            context: { toolTenant, stateTenant },
          });
          return violations;
        }
      }
    }

    // If stateContext is not provided
    if (!stateContext || typeof stateContext !== 'object') {
      if (params.require_state) {
        violations.push({
          ruleId,
          packId,
          severity,
          message: `State invariant rule '${ruleId}' requires system state context, but no state was provided.`,
          suggestedFix: `Pass current state context object to Aegis evaluate() to clear state invariant assertions.`,
          context: { missingState: true },
        });
      }
      return violations;
    }

    // Build unified evaluation context containing both state and params
    const evalContext: Record<string, unknown> = {
      params: toolCall.params,
      state: stateContext,
      ...toolCall.params,
      ...stateContext,
    };

    // 1. Verify Preconditions
    if (params.precondition) {
      const preconditionMet = this.dslEvaluator.evaluateExpression(
        params.precondition,
        evalContext
      );
      if (!preconditionMet) {
        violations.push({
          ruleId,
          packId,
          severity,
          message: `State precondition failed: '${params.precondition}' was not satisfied by current system state.`,
          suggestedFix: `Ensure system state satisfies precondition '${params.precondition}' before invoking '${toolCall.tool}'.`,
          context: { precondition: params.precondition, state: stateContext },
        });
      }
    }

    // 2. Verify State Transition Invariant Assertion
    if (params.assertion) {
      const invariantHolds = this.dslEvaluator.evaluateExpression(
        params.assertion,
        evalContext
      );
      if (!invariantHolds) {
        violations.push({
          ruleId,
          packId,
          severity,
          message: `System state invariant violated: '${params.assertion}' would be breached by this action.`,
          suggestedFix: `Action exceeds permitted state boundary. Invariant constraint: '${params.assertion}'.`,
          context: { assertion: params.assertion, state: stateContext, params: toolCall.params },
        });
      }
    }

    return violations;
  }

  private findNestedTenant(params: Record<string, unknown>, tenantField: string): unknown {
    return this.findNestedValue(params, tenantField);
  }

  private findNestedValue(
    obj: unknown,
    key: string,
    visited: Set<unknown> = new Set()
  ): unknown {
    if (!obj || typeof obj !== 'object' || visited.has(obj)) return undefined;
    visited.add(obj);
    const record = obj as Record<string, unknown>;

    if (key in record && record[key] !== undefined) {
      return record[key];
    }

    for (const val of Object.values(record)) {
      if (val && typeof val === 'object') {
        const found = this.findNestedValue(val, key, visited);
        if (found !== undefined) return found;
      }
    }

    return undefined;
  }
}

