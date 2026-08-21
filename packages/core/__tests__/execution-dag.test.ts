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

  it('enforces FIDES dual-lattice information flow control (confidentiality & integrity)', () => {
    // 1. Secret database read
    dag.addAction({
      id: 'node_db',
      agentId: 'analyst_01',
      actionType: 'query_db',
      timestamp: 1,
      securityLabel: {
        integrity: 'trusted',
        confidentiality: 'secret',
      },
    });

    // 2. Untrusted web scraping
    dag.addAction({
      id: 'node_web',
      agentId: 'analyst_01',
      actionType: 'web_scrape',
      timestamp: 2,
      securityLabel: {
        integrity: 'untrusted',
        confidentiality: 'public',
      },
    });

    // 3. Downstream aggregation transformer
    dag.addAction({
      id: 'node_summary',
      agentId: 'analyst_01',
      actionType: 'summarize_data',
      timestamp: 3,
    });

    // 4. Public web search egress sink
    dag.addAction({
      id: 'node_search',
      agentId: 'analyst_01',
      actionType: 'web_search',
      timestamp: 4,
    });

    // 5. Mutating database exec sink
    dag.addAction({
      id: 'node_mutate',
      agentId: 'analyst_01',
      actionType: 'database_exec',
      timestamp: 5,
    });

    // Wire data flows
    dag.addEdge({ sourceId: 'node_db', targetId: 'node_summary', type: 'data_flow' });
    dag.addEdge({ sourceId: 'node_web', targetId: 'node_summary', type: 'data_flow' });
    dag.addEdge({ sourceId: 'node_summary', targetId: 'node_search', type: 'data_flow' });
    dag.addEdge({ sourceId: 'node_summary', targetId: 'node_mutate', type: 'data_flow' });

    // Verify labels propagated correctly on summary node
    const summaryNode = dag.getAction('node_summary');
    expect(summaryNode?.securityLabel?.confidentiality).toBe('secret');
    expect(summaryNode?.securityLabel?.integrity).toBe('untrusted');

    // Run FIDES policy verification
    const violations = dag.verifyInformationFlow();
    expect(violations.length).toBeGreaterThanOrEqual(2);

    const confViolation = violations.find((v) => v.reason.includes('Confidentiality breach'));
    expect(confViolation).toBeDefined();

    const intViolation = violations.find((v) => v.reason.includes('Integrity breach'));
    expect(intViolation).toBeDefined();
  });
});
