import { describe, it, expect, beforeEach } from 'vitest';
import { ExecutionDAG, AgentAction, DAGEdge, ExfiltrationPattern } from '../src/graph/execution-dag';

describe('ExecutionDAG', () => {
  let dag: ExecutionDAG;

  beforeEach(() => {
    dag = new ExecutionDAG();
  });

  it('detects data exfiltration chains', () => {
    dag.addAction({ id: 'a1', agentId: 'ag1', actionType: 'read_file', timestamp: 1 });
    dag.addAction({ id: 'a2', agentId: 'ag1', actionType: 'format_data', timestamp: 2 });
    dag.addAction({ id: 'a3', agentId: 'ag1', actionType: 'send_email', timestamp: 3 });

    dag.addEdge({ sourceId: 'a1', targetId: 'a2', type: 'data_flow' });
    dag.addEdge({ sourceId: 'a2', targetId: 'a3', type: 'data_flow' });

    const pattern: ExfiltrationPattern = {
      sources: ['read_file', 'query_db'],
      transformers: ['format_data'],
      sinks: ['send_email', 'http_post']
    };

    const anomalies = dag.detectExfiltration(pattern);
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].type).toBe('DataExfiltration');
    expect(anomalies[0].involvedNodes).toEqual(['a1', 'a2', 'a3']);
  });

  it('detects circular agent delegation loops', () => {
    dag.addAction({ id: 'a1', agentId: 'ag1', actionType: 'delegate', timestamp: 1 });
    dag.addAction({ id: 'a2', agentId: 'ag2', actionType: 'delegate', timestamp: 2 });
    dag.addAction({ id: 'a3', agentId: 'ag3', actionType: 'delegate', timestamp: 3 });

    dag.addEdge({ sourceId: 'a1', targetId: 'a2', type: 'delegation' });
    dag.addEdge({ sourceId: 'a2', targetId: 'a3', type: 'delegation' });
    dag.addEdge({ sourceId: 'a3', targetId: 'a1', type: 'delegation' });

    const anomalies = dag.detectCycles();
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].type).toBe('CircularDelegation');
    expect(anomalies[0].involvedNodes).toContain('a1');
  });

  it('detects privilege escalation', () => {
    dag.addAction({ id: 'a1', agentId: 'ag1', actionType: 'delegate', timestamp: 1, privilegeLevel: 1 });
    dag.addAction({ id: 'a2', agentId: 'ag2', actionType: 'execute', timestamp: 2, privilegeLevel: 5 });

    dag.addEdge({ sourceId: 'a1', targetId: 'a2', type: 'delegation' });

    const anomalies = dag.detectPrivilegeEscalation();
    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].type).toBe('PrivilegeEscalation');
    expect(anomalies[0].involvedNodes).toEqual(['a1', 'a2']);
  });

  it('computes cascading blast radius', () => {
    dag.addAction({ id: 'a1', agentId: 'ag1', actionType: 'read', timestamp: 1 });
    dag.addAction({ id: 'a2', agentId: 'ag1', actionType: 'read', timestamp: 2 });
    dag.addAction({ id: 'a3', agentId: 'ag1', actionType: 'read', timestamp: 3 });

    dag.addEdge({ sourceId: 'a1', targetId: 'a2', type: 'data_flow' });
    dag.addEdge({ sourceId: 'a2', targetId: 'a3', type: 'data_flow' });

    const radius = dag.computeBlastRadius('a1');
    expect(radius).toEqual(expect.arrayContaining(['a1', 'a2', 'a3']));
  });
});
