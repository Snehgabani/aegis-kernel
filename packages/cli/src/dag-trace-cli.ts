/**
 * @file packages/cli/src/dag-trace-cli.ts
 * @description CLI command to render forensic Mermaid and ASCII graph traces of Execution DAGs.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { ExecutionDAG } from '@aegis-kernel/core';
import { DAGVisualizer } from '@aegis-kernel/diagnostics';

export function runDagTrace(dagPath: string, options: { format?: 'mermaid' | 'ascii'; output?: string } = {}): void {
  const resolved = path.resolve(process.cwd(), dagPath);
  if (!fs.existsSync(resolved)) {
    console.error(`\x1b[31mError: DAG file not found at ${resolved}\x1b[0m`);
    process.exitCode = 1;
    return;
  }

  try {
    const content = fs.readFileSync(resolved, 'utf8');
    const rawDag = JSON.parse(content);

    const dag = new ExecutionDAG();
    if (Array.isArray(rawDag.actions)) {
      for (const a of rawDag.actions) dag.addAction(a);
    }
    if (Array.isArray(rawDag.edges)) {
      for (const e of rawDag.edges) dag.addEdge(e);
    }

    const format = options.format ?? 'mermaid';
    console.log(`\x1b[36m🕸️  AEGIS CAUSAL EXECUTION DAG TRACER (${format.toUpperCase()})\x1b[0m\n`);

    const rendered = format === 'mermaid' ? DAGVisualizer.renderMermaid(dag) : DAGVisualizer.renderAscii(dag);

    console.log(rendered);

    if (options.output) {
      const outPath = path.resolve(process.cwd(), options.output);
      fs.writeFileSync(outPath, rendered, 'utf8');
      console.log(`\n\x1b[32m✔ Written DAG trace to: ${outPath}\x1b[0m`);
    }
  } catch (err: any) {
    console.error(`\x1b[31mDAG tracing failed: ${err?.message || err}\x1b[0m`);
    process.exitCode = 1;
  }
}
