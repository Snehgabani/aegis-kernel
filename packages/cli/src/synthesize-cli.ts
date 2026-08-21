/**
 * @file packages/cli/src/synthesize-cli.ts
 * @description CLI command to synthesize typed Aegis RulePacks from OpenAPI and MCP JSON schemas.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { SchemaInvariantSynthesizer } from '@aegis-kernel/core';

export function runSynthesize(schemaPath: string, options: { output?: string; format?: 'yaml' | 'json' } = {}): void {
  const resolved = path.resolve(process.cwd(), schemaPath);
  if (!fs.existsSync(resolved)) {
    console.error(`\x1b[31mError: Schema file not found at ${resolved}\x1b[0m`);
    process.exitCode = 1;
    return;
  }

  try {
    const content = fs.readFileSync(resolved, 'utf8');
    const rawSchema = JSON.parse(content);

    console.log(`\x1b[36m🧬 AEGIS INVARIANT SCHEMA SYNTHESIZER\x1b[0m`);
    console.log(`Analyzing tool schema: \x1b[33m${path.basename(resolved)}\x1b[0m...`);

    let pack;
    if (rawSchema.openapi || rawSchema.swagger) {
      // OpenAPI
      pack = SchemaInvariantSynthesizer.synthesizeFromOpenAPI(rawSchema);
    } else {
      // MCP Tool Definition
      pack = SchemaInvariantSynthesizer.synthesizePack(rawSchema);
    }

    console.log(`\x1b[32m✔ Synthesized ${pack.rules.length} deterministic invariant rules for pack '${pack.id}'\x1b[0m`);
    for (const r of pack.rules) {
      console.log(`  • [${r.severity.toUpperCase()}] ${r.id}: ${r.description}`);
    }

    if (options.output) {
      const outPath = path.resolve(process.cwd(), options.output);
      fs.writeFileSync(outPath, JSON.stringify(pack, null, 2), 'utf8');
      console.log(`\n\x1b[32m✔ Written synthesized pack to: ${outPath}\x1b[0m`);
    }
  } catch (err: any) {
    console.error(`\x1b[31mSynthesis failed: ${err?.message || err}\x1b[0m`);
    process.exitCode = 1;
  }
}
