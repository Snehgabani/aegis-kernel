import { describe, it, expect } from 'vitest';
import { SchemaInvariantSynthesizer } from '../src/synthesizer/schema-invariant-synthesizer.js';
import { AegisEngine } from '../src/engine.js';

describe('SchemaInvariantSynthesizer (Dynamic OpenAPI / MCP Rule Generation)', () => {
  const synthesizer = new SchemaInvariantSynthesizer({
    financialDefaultCeiling: 10000,
  });

  const wireTransferTool = {
    name: 'wire_transfer',
    description: 'Transfer funds between accounts',
    inputSchema: {
      type: 'object',
      properties: {
        amount: { type: 'number', minimum: 1, maximum: 5000 },
        currency: { type: 'string', enum: ['USD', 'EUR', 'GBP'] },
        recipient_iban: { type: 'string', maxLength: 34 },
        api_token: { type: 'string' },
      },
      required: ['amount', 'currency'],
    },
  };

  it('should synthesize numerical invariant bounds rules', () => {
    const rules = synthesizer.synthesizeRules(wireTransferTool);
    expect(rules.length).toBeGreaterThanOrEqual(2);

    const amountRule = rules.find((r) => r.id.includes('NUM-WIRE_TRANSFER-AMOUNT'));
    expect(amountRule).toBeDefined();
    expect(amountRule?.condition.type).toBe('numeric');
  });

  it('should synthesize plaintext credential exfiltration protection', () => {
    const rules = synthesizer.synthesizeRules(wireTransferTool);
    const piiRule = rules.find((r) => r.id.includes('PII-WIRE_TRANSFER-API_TOKEN'));
    expect(piiRule).toBeDefined();
    expect(piiRule?.condition.type).toBe('regex');
  });

  it('should synthesize self-contained RulePack and integrate into AegisEngine', () => {
    const pack = synthesizer.synthesizePack(wireTransferTool);
    expect(pack.id).toBe('@aegis/synthesized-wire_transfer');

    const engine = new AegisEngine({
      mode: 'enforce',
      packs: [pack],
    });

    const safeVerdict = engine.evaluate({
      tool: 'wire_transfer',
      params: { amount: 2500, currency: 'USD' },
    });
    expect(safeVerdict.allowed).toBe(true);

    const overspendVerdict = engine.evaluate({
      tool: 'wire_transfer',
      params: { amount: 99999, currency: 'USD' },
    });
    expect(overspendVerdict.allowed).toBe(false);
    expect(overspendVerdict.violations.some((v) => v.ruleId.includes('NUM-WIRE_TRANSFER-AMOUNT'))).toBe(true);
  });
});
