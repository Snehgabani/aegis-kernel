export type Effect = 'permit' | 'forbid';

export interface PolicyStatement {
  effect: Effect;
  principal?: string;
  action?: string;
  resource?: string;
  conditions?: ASTNode;
}

export interface CedarPolicy {
  id: string;
  statements: PolicyStatement[];
}

export type ASTNode = 
  | { type: 'Literal'; value: any }
  | { type: 'Identifier'; name: string }
  | { type: 'BinaryExpression'; operator: string; left: ASTNode; right: ASTNode }
  | { type: 'UnaryExpression'; operator: string; argument: ASTNode };

export interface PolicyEvaluationResult {
  decision: 'Allow' | 'Deny';
  reason?: string;
  matchedPolicies: string[];
}

export interface EvaluationContext {
  principal?: string;
  action?: string;
  resource?: string;
  context?: Record<string, any>;
}

export class PolicyEngine {
  private policies: Map<string, CedarPolicy> = new Map();

  addPolicy(policy: CedarPolicy) {
    this.policies.set(policy.id, policy);
  }

  evaluate(evalCtx: EvaluationContext): PolicyEvaluationResult {
    let finalDecision: 'Allow' | 'Deny' = 'Deny';
    const matchedPolicies: string[] = [];

    for (const [id, policy] of this.policies.entries()) {
      for (const statement of policy.statements) {
        if (this.matchStatement(statement, evalCtx)) {
          if (statement.effect === 'forbid') {
            return {
              decision: 'Deny',
              reason: `Explicitly forbidden by policy ${id}`,
              matchedPolicies: [id]
            };
          }
          if (statement.effect === 'permit') {
            finalDecision = 'Allow';
            matchedPolicies.push(id);
          }
        }
      }
    }

    return {
      decision: finalDecision,
      reason: finalDecision === 'Deny' ? 'Default Deny' : 'Permitted',
      matchedPolicies
    };
  }

  private matchStatement(statement: PolicyStatement, evalCtx: EvaluationContext): boolean {
    if (statement.principal && statement.principal !== '*' && statement.principal !== evalCtx.principal) {
      return false;
    }
    if (statement.action && statement.action !== '*' && statement.action !== evalCtx.action) {
      return false;
    }
    if (statement.resource && statement.resource !== '*' && statement.resource !== evalCtx.resource) {
      return false;
    }
    
    if (statement.conditions) {
      return this.evaluateCondition(statement.conditions, evalCtx.context || {});
    }
    
    return true;
  }

  private evaluateCondition(node: ASTNode, context: Record<string, any>): boolean {
    const val = this.evaluateNode(node, context);
    return Boolean(val);
  }

  private evaluateNode(node: ASTNode, context: Record<string, any>): any {
    switch (node.type) {
      case 'Literal':
        return node.value;
      case 'Identifier':
        const parts = node.name.split('.');
        let current: any = context;
        for (const part of parts) {
          if (current == null) return undefined;
          current = current[part];
        }
        return current;
      case 'UnaryExpression':
        const arg = this.evaluateNode(node.argument, context);
        if (node.operator === '!') return !arg;
        throw new Error(`Unsupported unary operator: ${node.operator}`);
      case 'BinaryExpression':
        const left = this.evaluateNode(node.left, context);
        // short circuit
        if (node.operator === '&&') {
          return left && this.evaluateNode(node.right, context);
        }
        if (node.operator === '||') {
          return left || this.evaluateNode(node.right, context);
        }
        const right = this.evaluateNode(node.right, context);
        switch (node.operator) {
          case '==': return left == right;
          case '!=': return left != right;
          case '===': return left === right;
          case '!==': return left !== right;
          case '<': return left < right;
          case '<=': return left <= right;
          case '>': return left > right;
          case '>=': return left >= right;
          case 'in': return Array.isArray(right) ? right.includes(left) : left in right;
          case 'contains': return Array.isArray(left) || typeof left === 'string' ? left.includes(right) : false;
          default:
            throw new Error(`Unsupported binary operator: ${node.operator}`);
        }
      default:
        throw new Error(`Unsupported node type`);
    }
  }
}
