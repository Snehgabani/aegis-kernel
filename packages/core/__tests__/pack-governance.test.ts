/**
 * Pack Governance Guard
 *
 * BUILTIN_PACKS in rule-loader.ts is the single source of truth used at
 * runtime. The human-editable YAML files under packages/core/packs/ MUST
 * mirror it exactly — otherwise edits silently do nothing (drift).
 *
 * This test parses every YAML pack and diffs it against BUILTIN_PACKS.
 * Any divergence fails CI, forcing the two to be updated together.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';
import { BUILTIN_PACKS } from '../src/rule-loader.js';
import type { RulePack } from '../src/types.js';

const PACKS_DIR = path.resolve(import.meta.dirname, '..', 'packs');

function collectPacks(): Array<{ ref: string; yamlPack: RulePack }> {
  const out: Array<{ ref: string; yamlPack: RulePack }> = [];
  for (const file of fs.readdirSync(PACKS_DIR).filter((f) => f.endsWith('.yaml'))) {
    const raw = fs.readFileSync(path.join(PACKS_DIR, file), 'utf8');
    const parsed = yaml.load(raw) as RulePack;
    out.push({ ref: `@aegis/${parsed.id}`, yamlPack: parsed });
  }
  return out;
}

// Canonicalize a pack into a comparable shape (sorted rule ids, sorted arrays).
function canonical(pack: RulePack): unknown {
  return {
    id: pack.id,
    version: pack.version,
    rules: pack.rules
      .map((r) => ({
        id: r.id,
        severity: r.severity,
        description: r.description,
        suggestedFix: r.suggestedFix,
        condition: {
          type: r.condition.type,
          params: r.condition.params,
        },
      }))
      .sort((a, b) => a.id.localeCompare(b.id)),
  };
}

describe('Pack governance: YAML files must mirror BUILTIN_PACKS', () => {
  it('every YAML pack exists in BUILTIN_PACKS with identical rules', () => {
    const yamlPacks = collectPacks();
    expect(yamlPacks.length).toBeGreaterThan(0);

    for (const { ref, yamlPack } of yamlPacks) {
      const builtin = BUILTIN_PACKS[ref];
      expect(builtin, `YAML pack ${ref} missing from BUILTIN_PACKS`).toBeDefined();
      expect(canonical(builtin), `rules of ${ref} drifted between YAML and BUILTIN_PACKS`).toEqual(
        canonical(yamlPack)
      );
    }
  });

  it('every BUILTIN_PACKS entry has a matching YAML file', () => {
    const yamlIds = new Set(collectPacks().map((p) => p.yamlPack.id));
    for (const ref of Object.keys(BUILTIN_PACKS)) {
      const id = ref.replace('@aegis/', '');
      expect(yamlIds.has(id), `BUILTIN_PACKS entry ${ref} has no YAML file in packs/`).toBe(true);
    }
  });
});

describe('Pack governance: external schemas must match the runtime', () => {
  it('every YAML pack validates against .aegis/schemas/aegis-pack.schema.json', () => {
    const AjvModule = require('ajv');
    const AjvClass = AjvModule.default ?? AjvModule;
    const ajv = new AjvClass({ allErrors: true });
    const schema = JSON.parse(
      fs.readFileSync(path.resolve(import.meta.dirname, '..', '..', '..', '.aegis', 'schemas', 'aegis-pack.schema.json'), 'utf8')
    );
    const validate = ajv.compile(schema);

    for (const { ref, yamlPack } of collectPacks()) {
      const ok = validate(yamlPack);
      expect(ok, `${ref} fails .aegis/schemas/aegis-pack.schema.json: ${JSON.stringify(validate.errors?.[0])}`).toBe(true);
    }
  });

  it('the init template config validates against aegis-config.schema.json', () => {
    const AjvModule = require('ajv');
    const AjvClass = AjvModule.default ?? AjvModule;
    const ajv = new AjvClass({ allErrors: true, allowUnionTypes: true });
    const schema = JSON.parse(
      fs.readFileSync(path.resolve(import.meta.dirname, '..', '..', '..', '.aegis', 'schemas', 'aegis-config.schema.json'), 'utf8')
    );
    const validate = ajv.compile(schema);

    const initSrc = fs.readFileSync(path.resolve(import.meta.dirname, '..', '..', 'cli', 'src', 'init.ts'), 'utf8');
    // defaultYaml is a JS template literal: extract between the backticks.
    const m = initSrc.match(/defaultYaml = `([\s\S]*?)`;/);
    expect(m, 'init.ts must define defaultYaml as a template literal').not.toBeNull();
    const template = yaml.load(m![1]!) as Record<string, unknown>;
    const ok = validate(template);
    expect(ok, `init template fails aegis-config.schema.json: ${JSON.stringify(validate.errors?.[0])}`).toBe(true);
    // The key the engine actually reads (failPolicy) must be the camelCase form.
    expect(template.failPolicy).toBeDefined();
  });
});
