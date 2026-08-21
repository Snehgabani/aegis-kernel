/**
 * @file packages/core/src/synthesizer/schema-invariant-synthesizer.ts
 * @description Automatically synthesizes deterministic AST and numerical invariant validation rules
 * from arbitrary OpenAPI 3.0/3.1 and Model Context Protocol (MCP) JSON schemas at tool registration time.
 */

import type { Rule, RulePack } from '../types.js';

export interface JSONSchemaProperty {
  type?: string | string[];
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number;
  exclusiveMaximum?: number;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  enum?: Array<string | number>;
  format?: string;
  description?: string;
  items?: JSONSchemaProperty;
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
}

export interface ToolSchemaDefinition {
  name: string;
  description?: string;
  parameters?: {
    type?: string;
    properties?: Record<string, JSONSchemaProperty>;
    required?: string[];
  };
  inputSchema?: {
    type?: string;
    properties?: Record<string, JSONSchemaProperty>;
    required?: string[];
  };
}

export interface SynthesisOptions {
  strictNumericalBounds?: boolean;
  defaultMaxStringLength?: number;
  autoDetectFinancialCeilings?: boolean;
  financialDefaultCeiling?: number;
  piiParamKeywords?: string[];
}

export class SchemaInvariantSynthesizer {
  private options: Required<SynthesisOptions>;

  constructor(options: SynthesisOptions = {}) {
    this.options = {
      strictNumericalBounds: options.strictNumericalBounds ?? true,
      defaultMaxStringLength: options.defaultMaxStringLength ?? 10000,
      autoDetectFinancialCeilings: options.autoDetectFinancialCeilings ?? true,
      financialDefaultCeiling: options.financialDefaultCeiling ?? 50000,
      piiParamKeywords: options.piiParamKeywords ?? ['ssn', 'password', 'secret', 'token', 'credit_card', 'api_key', 'private_key'],
    };
  }

  /**
   * Synthesize a collection of deterministic invariant rules from a tool schema definition.
   */
  public synthesizeRules(toolDef: ToolSchemaDefinition): Rule[] {
    const rules: Rule[] = [];
    const toolName = toolDef.name;
    const schema = toolDef.inputSchema ?? toolDef.parameters;

    if (!schema || !schema.properties) {
      return rules;
    }

    const properties = schema.properties;

    for (const [propName, propDef] of Object.entries(properties)) {
      // 1. Numerical Invariant Bounds Synthesis
      if (propDef.type === 'number' || propDef.type === 'integer') {
        const isFinancial =
          this.options.autoDetectFinancialCeilings &&
          /(amount|spend|cost|price|balance|total|transfer|fee|cents|dollars|usd)/i.test(propName);

        const minVal = propDef.minimum ?? (isFinancial ? 0 : undefined);
        const maxVal = propDef.maximum ?? (isFinancial ? this.options.financialDefaultCeiling : undefined);

        if (minVal !== undefined || maxVal !== undefined) {
          rules.push({
            id: `SYN-NUM-${toolName}-${propName}`.toUpperCase(),
            severity: 'critical',
            description: `Auto-synthesized numeric invariant for ${toolName}.${propName}`,
            condition: {
              type: 'numeric',
              params: {
                field: propName,
                min: minVal,
                max: maxVal,
              },
            },
            suggestedFix: `Clamp ${propName} within allowable range [${minVal ?? '-∞'}, ${maxVal ?? '+∞'}].`,
          });
        }
      }

      // 2. Sensitive PII / Plaintext Secret Parameter Protection
      const isSensitiveKey = this.options.piiParamKeywords.some((kw) =>
        propName.toLowerCase().includes(kw)
      );

      if (isSensitiveKey) {
        rules.push({
          id: `SYN-PII-${toolName}-${propName}`.toUpperCase(),
          severity: 'critical',
          description: `Auto-synthesized credential protection for ${toolName}.${propName}`,
          condition: {
            type: 'regex',
            params: {
              field: propName,
              patterns: [
                'sk-[a-zA-Z0-9]{20,}',
                'AKIA[0-9A-Z]{16}',
                'ghp_[a-zA-Z0-9]{36}',
              ],
              match_action: 'block',
            },
          },
          suggestedFix: `Do not pass raw plaintext API credentials in parameter '${propName}'.`,
        });
      }
    }

    // 3. Schema Structure Rule
    if (schema.type === 'object' && Object.keys(properties).length > 0) {
      rules.push({
        id: `SYN-SCHEMA-${toolName}`.toUpperCase(),
        severity: 'warning',
        description: `Auto-synthesized JSON schema structure validator for ${toolName}`,
        condition: {
          type: 'json_schema',
          params: {
            schema: {
              type: 'object',
              properties,
              required: schema.required ?? [],
            },
            strict: false,
          },
        },
        suggestedFix: `Verify tool parameters match synthesized schema for '${toolName}'.`,
      });
    }

    return rules;
  }

  /**
   * Synthesize a self-contained RulePack ready to be registered directly with AegisEngine.
   */
  public synthesizePack(toolDef: ToolSchemaDefinition, version = '1.0.0'): RulePack {
    const rules = this.synthesizeRules(toolDef);
    return {
      id: `@aegis/synthesized-${toolDef.name}`,
      name: `Synthesized Guard for ${toolDef.name}`,
      version,
      description: `Auto-generated deterministic invariant pack from tool schema '${toolDef.name}'`,
      rules,
    };
  }
}
