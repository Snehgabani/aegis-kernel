import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEngine, CedarPolicy } from '../src/policy/policy-as-code';

describe('PolicyEngine', () => {
  let engine: PolicyEngine;

  beforeEach(() => {
    engine = new PolicyEngine();
  });

  it('evaluates simple permit statement', () => {
    engine.addPolicy({
      id: 'pol1',
      statements: [
        {
          effect: 'permit',
          principal: 'user1',
          action: 'read',
          resource: 'doc1'
        }
      ]
    });

    const res1 = engine.evaluate({ principal: 'user1', action: 'read', resource: 'doc1' });
    expect(res1.decision).toBe('Allow');
    expect(res1.matchedPolicies).toContain('pol1');

    const res2 = engine.evaluate({ principal: 'user2', action: 'read', resource: 'doc1' });
    expect(res2.decision).toBe('Deny');
  });

  it('evaluates conditions (ABAC)', () => {
    engine.addPolicy({
      id: 'pol2',
      statements: [
        {
          effect: 'permit',
          conditions: {
            type: 'BinaryExpression',
            operator: '==',
            left: { type: 'Identifier', name: 'user.department' },
            right: { type: 'Literal', value: 'IT' }
          }
        }
      ]
    });

    const res1 = engine.evaluate({ context: { user: { department: 'IT' } } });
    expect(res1.decision).toBe('Allow');

    const res2 = engine.evaluate({ context: { user: { department: 'HR' } } });
    expect(res2.decision).toBe('Deny');
  });

  it('evaluates explicit forbid overriding permit', () => {
    engine.addPolicy({
      id: 'pol3',
      statements: [
        {
          effect: 'permit',
          principal: 'user1'
        },
        {
          effect: 'forbid',
          principal: 'user1',
          action: 'delete'
        }
      ]
    });

    const res1 = engine.evaluate({ principal: 'user1', action: 'read' });
    expect(res1.decision).toBe('Allow');

    const res2 = engine.evaluate({ principal: 'user1', action: 'delete' });
    expect(res2.decision).toBe('Deny');
  });

  it('supports complex boolean logic and contains operator', () => {
    engine.addPolicy({
      id: 'pol4',
      statements: [
        {
          effect: 'permit',
          conditions: {
            type: 'BinaryExpression',
            operator: '&&',
            left: {
              type: 'BinaryExpression',
              operator: '>',
              left: { type: 'Identifier', name: 'age' },
              right: { type: 'Literal', value: 18 }
            },
            right: {
              type: 'BinaryExpression',
              operator: 'contains',
              left: { type: 'Identifier', name: 'roles' },
              right: { type: 'Literal', value: 'admin' }
            }
          }
        }
      ]
    });

    const res1 = engine.evaluate({ context: { age: 20, roles: ['user', 'admin'] } });
    expect(res1.decision).toBe('Allow');

    const res2 = engine.evaluate({ context: { age: 15, roles: ['admin'] } });
    expect(res2.decision).toBe('Deny');
  });
});
