import { describe, it, expect } from 'vitest';
import { ExecutionDAG } from '@aegis-kernel/core';
import { DAGVisualizer } from '../src/dag-visualizer.js';

describe('DAGVisualizer (Forensic Graph Rendering)', () => {
  it('renders Mermaid flowchart with FIDES security tags and edge mappings', () => {
    const dag = new ExecutionDAG();

    dag.addAction({
      id: 'step_1',
      agentId: 'ag_01',
      actionType: 'read_secret_keys',
      timestamp: 1,
      securityLabel: { integrity: 'trusted', confidentiality: 'secret' },
    });

    dag.addAction({
      id: 'step_2',
      agentId: 'ag_01',
      actionType: 'http_post',
      timestamp: 2,
    });

    dag.addEdge({ sourceId: 'step_1', targetId: 'step_2', type: 'data_flow' });

    const mermaidStr = DAGVisualizer.renderMermaid(dag);
    expect(mermaidStr).toContain('flowchart TD');
    expect(mermaidStr).toContain('node_step_1["read_secret_keys (step_1) [SECRET]"]');
    expect(mermaidStr).toContain('node_step_1 -->|data_flow| node_step_2');
    expect(mermaidStr).toContain('classDef anomalyNode');
  });

  it('renders ASCII diagnostic trace', () => {
    const dag = new ExecutionDAG();
    dag.addAction({
      id: 'a1',
      agentId: 'ag1',
      actionType: 'query_db',
      timestamp: 1,
    });

    const ascii = DAGVisualizer.renderAscii(dag);
    expect(ascii).toContain('Execution DAG Diagnostic Trace:');
    expect(ascii).toContain('Node: a1 (query_db)');
  });
});
