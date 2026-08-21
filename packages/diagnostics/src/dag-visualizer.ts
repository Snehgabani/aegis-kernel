/**
 * @file packages/diagnostics/src/dag-visualizer.ts
 * @description Forensic Visualizer for Causal Execution DAGs, rendering Mermaid diagrams,
 * SVG graphs, and ASCII trees with FIDES security label color coding.
 */

import type { ExecutionDAG } from '@aegis-kernel/core';

export interface RenderOptions {
  theme?: 'dark' | 'light';
  highlightAnomalies?: boolean;
  includeLabels?: boolean;
}

export class DAGVisualizer {
  /**
   * Renders the ExecutionDAG as a standard Mermaid flowchart markdown string.
   */
  public static renderMermaid(dag: ExecutionDAG, options: RenderOptions = {}): string {
    const actions = dag.getActions();
    const edges = dag.getEdges();
    const highlightAnomalies = options.highlightAnomalies ?? true;

    const lines: string[] = ['flowchart TD'];

    // 1. Declare Nodes with FIDES security tags
    for (const act of actions) {
      const label = act.securityLabel;
      const confTag = label ? ` [${label.confidentiality.toUpperCase()}]` : '';
      const nodeLabel = `"${act.actionType} (${act.id})${confTag}"`;
      lines.push(`  node_${act.id}[${nodeLabel}]`);
    }

    // 2. Declare Edges
    for (const edge of edges) {
      const edgeLabel = edge.type === 'data_flow' ? '|data_flow|' : '|delegation|';
      lines.push(`  node_${edge.sourceId} -->${edgeLabel} node_${edge.targetId}`);
    }

    // 3. Highlight Anomalies / Violations if requested
    if (highlightAnomalies) {
      const ifcViolations = dag.verifyInformationFlow();
      const cycles = dag.detectCycles();
      const allAnomalyNodeIds = new Set<string>();

      for (const an of [...ifcViolations, ...cycles]) {
        for (const nid of an.involvedNodes) {
          allAnomalyNodeIds.add(nid);
        }
      }

      if (allAnomalyNodeIds.size > 0) {
        lines.push('');
        lines.push('  %% High-Risk Anomaly Highlighting');
        lines.push('  classDef anomalyNode fill:#ff4444,stroke:#cc0000,stroke-width:3px,color:#ffffff;');
        for (const nid of allAnomalyNodeIds) {
          lines.push(`  class node_${nid} anomalyNode;`);
        }
      }
    }

    return lines.join('\n');
  }

  /**
   * Renders the ExecutionDAG as an ASCII diagnostic tree string.
   */
  public static renderAscii(dag: ExecutionDAG): string {
    const actions = dag.getActions();
    const edges = dag.getEdges();

    const output: string[] = ['Execution DAG Diagnostic Trace:'];
    for (const act of actions) {
      const label = act.securityLabel;
      const secStr = label ? ` [Integrity: ${label.integrity}, Conf: ${label.confidentiality}]` : '';
      output.push(`  ├── Node: ${act.id} (${act.actionType})${secStr}`);
      const outgoing = edges.filter((e) => e.sourceId === act.id);
      for (const e of outgoing) {
        output.push(`  │    └── ${e.type} ──▶ ${e.targetId}`);
      }
    }

    return output.join('\n');
  }
}
