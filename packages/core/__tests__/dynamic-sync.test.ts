import { describe, it, expect } from 'vitest';
import { AegisEngine, AegisDynamicSyncManager, type RulePack } from '../src/index.js';

describe('Aegis Dynamic Rule Pack Hot-Reloading & Sync', () => {
  it('should dynamically hot-swap rule packs on running engine without restarting', () => {
    const engine = new AegisEngine({
      mode: 'enforce',
      packs: ['@aegis/sql-guard'],
    });

    const initialHash = engine.getPolicyCommitmentHash();

    // 1. Initial State: Only SQL Guard is active (Financial call should be allowed)
    const finCall = {
      tool: 'send_payout',
      params: { amount: 50000 },
    };
    const v1 = engine.evaluate(finCall);
    expect(v1.allowed).toBe(true);

    // 2. Hot-Swap: Add Finance Guard dynamically
    const syncManager = new AegisDynamicSyncManager({ engine });

    const newFinancePack: RulePack = {
      id: 'custom-finance-guard',
      name: 'Custom Finance Guard',
      version: '2.0.0',
      rules: [
        {
          id: 'FIN-CUSTOM-01',
          severity: 'critical',
          description: 'Maximum payout ceiling $5,000',
          condition: {
            type: 'numeric',
            params: { field: 'amount', max: 5000 },
          },
        },
      ],
    };

    const res = syncManager.hotSwapRules([newFinancePack]);
    expect(res.applied).toBe(true);
    expect(res.ruleCount).toBe(1);
    expect(res.policyHash).not.toBe(initialHash);

    // 3. Post-Swap State: Financial call should now be BLOCKED
    const v2 = engine.evaluate(finCall);
    expect(v2.allowed).toBe(false);
    expect(v2.violations[0].ruleId).toBe('FIN-CUSTOM-01');
    expect(v2.proofHash).toBeDefined();
  });
});
