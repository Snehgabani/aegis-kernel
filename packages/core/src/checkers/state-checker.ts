import type { AegisViolation, ToolCall } from '../types.js';
import { CustomChecker } from './custom-checker.js';

export interface StateInvariantConditionParams {
  target_field?: string; // Optional field on toolCall.params (e.g. 'amount')
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
    stateContext?: Record<string, unknown>
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];

    // If this state rule targets a specific field (e.g. 'amount') and the tool call doesn't have it, skip
    if (params.target_field && !(params.target_field in toolCall.params)) {
      return violations;
    }

    // If stateContext is not provided
    if (!stateContext || typeof stateContext !== 'object') {
      if (params.require_state) {
        violations.push({
          ruleId,
          packId,
          severity: 'critical',
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
          severity: 'critical',
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
          severity: 'critical',
          message: `System state invariant violated: '${params.assertion}' would be breached by this action.`,
          suggestedFix: `Action exceeds permitted state boundary. Invariant constraint: '${params.assertion}'.`,
          context: { assertion: params.assertion, state: stateContext, params: toolCall.params },
        });
      }
    }

    return violations;
  }
}
