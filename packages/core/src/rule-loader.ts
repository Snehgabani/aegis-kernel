import * as fs from 'node:fs';
import * as yaml from 'js-yaml';
import AjvModule from 'ajv';
import type { RulePack } from './types.js';

const AjvClass: typeof import('ajv').default = (AjvModule as any).default ?? AjvModule;
const ajv = new (AjvClass as any)();

const RULE_PACK_SCHEMA = {
  type: 'object',
  required: ['id', 'name', 'version', 'rules'],
  properties: {
    id: { type: 'string', pattern: '^[a-zA-Z0-9_/@.-]+$' },
    name: { type: 'string' },
    version: { type: 'string' },
    description: { type: 'string' },
    rules: {
      type: 'array',
      items: {
        type: 'object',
        required: ['id', 'severity', 'description', 'condition'],
        properties: {
          id: { type: 'string' },
          severity: { enum: ['critical', 'warning', 'info'] },
          description: { type: 'string' },
          suggestedFix: { type: 'string' },
          condition: {
            type: 'object',
            required: ['type', 'params'],
            properties: {
              type: {
                enum: ['sql_ast', 'json_schema', 'regex', 'numeric', 'custom', 'state_invariant'],
              },
              params: { type: 'object' },
            },
          },
        },
      },
    },
  },
};

const validatePackSchema = ajv.compile(RULE_PACK_SCHEMA);

// Inlined Built-in Launch Packs (Available with zero file-system dependencies)
// Built-in launch packs: the YAML files in packages/core/packs/ are the
// single source of truth. scripts/gen-packs.mjs embeds their contents into
// packs.generated.ts at build time, so BUILTIN_PACKS works in ANY environment
// (bundled CLI, GitHub Action, esbuild consumers) with zero filesystem
// dependency and zero drift. pack-governance.test.ts enforces YAML <-> embed
// synchronization.
import { EMBEDDED_PACK_YAMLS } from './packs.generated.js';

export const BUILTIN_PACKS: Record<string, RulePack> = (() => {
  const packs: Record<string, RulePack> = {};
  for (const [ref, rawYaml] of Object.entries(EMBEDDED_PACK_YAMLS)) {
    try {
      const parsed = yaml.load(rawYaml) as RulePack;
      if (validatePackSchema(parsed)) {
        packs[ref] = parsed;
      }
    } catch {
      // skip malformed pack; governance test will surface it
    }
  }
  return packs;
})();;

export class RulePackLoader {
  public static loadPack(packRef: string | RulePack): RulePack | null {
    if (typeof packRef !== 'string') {
      if (this.validatePack(packRef)) {
        return packRef;
      }
      return null;
    }

    if (packRef in BUILTIN_PACKS) {
      return BUILTIN_PACKS[packRef];
    }
    const withPrefix = `@aegis/${packRef}`;
    if (withPrefix in BUILTIN_PACKS) {
      return BUILTIN_PACKS[withPrefix];
    }

    try {
      if (fs.existsSync(packRef)) {
        const fileContent = fs.readFileSync(packRef, 'utf8');
        const parsed = yaml.load(fileContent) as RulePack;
        if (this.validatePack(parsed)) {
          return parsed;
        }
      }
    } catch {
      // Return null on failure
    }

    return null;
  }

  public static validatePack(pack: unknown): pack is RulePack {
    if (!pack || typeof pack !== 'object') return false;
    const isValid = validatePackSchema(pack);
    return Boolean(isValid);
  }
}
