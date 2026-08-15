import AjvModule from 'ajv';
import type { AegisViolation, JsonSchemaConditionParams, ToolCall } from '../types.js';

const AjvClass: typeof import('ajv').default = (AjvModule as any).default ?? AjvModule;

export class SchemaChecker {
  private ajv: any;
  private schemaCache: Map<string, any>;

  constructor() {
    this.ajv = new (AjvClass as any)({ allErrors: true, coerceTypes: false });
    this.schemaCache = new Map();
  }

  public evaluate(
    ruleId: string,
    packId: string,
    params: JsonSchemaConditionParams,
    toolCall: ToolCall
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];

    try {
      const cacheKey = JSON.stringify(params.schema);
      let validate = this.schemaCache.get(cacheKey);

      if (!validate) {
        validate = this.ajv.compile(params.schema);
        this.schemaCache.set(cacheKey, validate);
      }

      const valid = validate(toolCall.params);

      if (!valid && validate.errors) {
        for (const err of validate.errors) {
          const property = err.instancePath || err.params?.missingProperty || 'root';
          violations.push({
            ruleId,
            packId,
            severity: 'critical',
            message: `Parameter schema violation at '${property}': ${err.message}`,
            suggestedFix: `Ensure parameters match the required schema definition for tool '${toolCall.tool}'.`,
            context: {
              property: String(property),
              schemaPath: err.schemaPath,
              message: err.message,
            },
          });
        }
      }
    } catch (err: any) {
      violations.push({
        ruleId,
        packId,
        severity: 'warning',
        message: `Schema validation evaluation error: ${err.message}`,
        context: { error: err.message },
      });
    }

    return violations;
  }
}
