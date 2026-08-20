/**
 * @file packages/core/__tests__/exfiltration-integration.test.ts
 * @description Integration tests for cross-cutting Aegis features
 *
 * Tests:
 * 1. ExecutionDAG exfiltration chain detection
 * 2. ConversationTracker crescendo attack detection
 * 3. Combined: crescendo + exfiltration chain
 */

import { describe, it, expect } from 'vitest';
import { ExecutionDAG } from '../src/graph/execution-dag.js';
import { ConversationTracker } from '../src/state/conversation-tracker.js';

describe('ExecutionDAG — Exfiltration Chain Detection', () => {
  it('should detect a read_file -> format_data -> send_email exfiltration chain', () => {
    const dag = new ExecutionDAG();

    dag.addAction({
      id: 'act_1',
      agentId: 'agent_a',
      actionType: 'read_file',
      resource: '/etc/passwd',
      timestamp: Date.now(),
    });
    dag.addAction({
      id: 'act_2',
      agentId: 'agent_a',
      actionType: 'format_data',
      resource: '',
      timestamp: Date.now() + 50,
    });
    dag.addAction({
      id: 'act_3',
      agentId: 'agent_a',
      actionType: 'send_email',
      resource: 'attacker@evil.com',
      timestamp: Date.now() + 100,
    });

    dag.addEdge({ sourceId: 'act_1', targetId: 'act_2', type: 'data_flow' });
    dag.addEdge({ sourceId: 'act_2', targetId: 'act_3', type: 'data_flow' });

    const anomalies = dag.detectExfiltration({
      sources: ['read_file'],
      transformers: ['format_data', 'encode_data'],
      sinks: ['send_email', 'upload_file', 'post_message'],
    });

    expect(anomalies.length).toBeGreaterThan(0);
    expect(anomalies[0].type).toBe('DataExfiltration');
  });

  it('should detect a 3-step read_file -> format_data -> send_email chain', () => {
    const dag = new ExecutionDAG();

    dag.addAction({
      id: 'act_1',
      agentId: 'agent_a',
      actionType: 'read_file',
      resource: '/tmp/credentials.json',
      timestamp: Date.now(),
    });
    dag.addAction({
      id: 'act_2',
      agentId: 'agent_a',
      actionType: 'format_data',
      resource: '',
      timestamp: Date.now() + 100,
    });
    dag.addAction({
      id: 'act_3',
      agentId: 'agent_a',
      actionType: 'send_email',
      resource: 'exfil@target.com',
      timestamp: Date.now() + 200,
    });

    dag.addEdge({ sourceId: 'act_1', targetId: 'act_2', type: 'data_flow' });
    dag.addEdge({ sourceId: 'act_2', targetId: 'act_3', type: 'data_flow' });

    const anomalies = dag.detectExfiltration({
      sources: ['read_file'],
      transformers: ['format_data', 'encode_data'],
      sinks: ['send_email', 'upload_file', 'post_message'],
    });

    expect(anomalies.length).toBeGreaterThan(0);
    expect(anomalies[0].involvedNodes).toContain('act_1');
    expect(anomalies[0].involvedNodes).toContain('act_3');
  });

  it('should not flag standalone read_file without a sink', () => {
    const dag = new ExecutionDAG();

    dag.addAction({
      id: 'act_1',
      agentId: 'agent_a',
      actionType: 'read_file',
      resource: '/etc/config.json',
      timestamp: Date.now(),
    });

    const anomalies = dag.detectExfiltration({
      sources: ['read_file'],
      transformers: ['format_data'],
      sinks: ['send_email', 'upload_file'],
    });

    expect(anomalies.length).toBe(0);
  });

  it('should not flag read_file -> query_db chain (no exfiltration sink)', () => {
    const dag = new ExecutionDAG();

    dag.addAction({
      id: 'act_1',
      agentId: 'agent_a',
      actionType: 'read_file',
      resource: '/tmp/data.csv',
      timestamp: Date.now(),
    });
    dag.addAction({
      id: 'act_2',
      agentId: 'agent_a',
      actionType: 'query_db',
      resource: 'INSERT INTO imports VALUES (...)',
      timestamp: Date.now() + 100,
    });

    dag.addEdge({ sourceId: 'act_1', targetId: 'act_2', type: 'data_flow' });

    const anomalies = dag.detectExfiltration({
      sources: ['read_file'],
      transformers: ['format_data'],
      sinks: ['send_email', 'upload_file'],
    });

    expect(anomalies.length).toBe(0);
  });

  it('should detect cross-agent delegation exfiltration chain (with data_flow)', () => {
    const dag = new ExecutionDAG();

    // Agent A reads sensitive data
    dag.addAction({
      id: 'act_1',
      agentId: 'agent_a',
      actionType: 'read_file',
      resource: '/etc/shadow',
      timestamp: Date.now(),
    });

    // Agent A delegates to Agent B for formatting (data flows via delegation)
    dag.addAction({
      id: 'act_2',
      agentId: 'agent_b',
      actionType: 'format_data',
      resource: '',
      timestamp: Date.now() + 100,
    });

    // Agent B sends to external sink
    dag.addAction({
      id: 'act_3',
      agentId: 'agent_b',
      actionType: 'send_email',
      resource: 'external@domain.com',
      timestamp: Date.now() + 200,
    });

    dag.addEdge({ sourceId: 'act_1', targetId: 'act_2', type: 'data_flow' });
    dag.addEdge({ sourceId: 'act_2', targetId: 'act_3', type: 'data_flow' });

    const anomalies = dag.detectExfiltration({
      sources: ['read_file'],
      transformers: ['format_data'],
      sinks: ['send_email', 'upload_file'],
    });

    expect(anomalies.length).toBeGreaterThan(0);
    expect(anomalies[0].type).toBe('DataExfiltration');
  });
});


describe('ConversationTracker — Crescendo Attack Detection', () => {
  it('should allow low-risk turns to continue', () => {
    const tracker = new ConversationTracker({
      driftThreshold: 0.75,
      riskDecayFactor: 0.85,
    });

    const result = tracker.addTurn({
      turnIndex: 0,
      toolName: 'search_kb',
      params: { query: 'customer FAQ' },
      riskContribution: 0.1,
      timestamp: Date.now(),
    });

    expect(result.action).toBe('CONTINUE');
  });

  it('should warn when approaching risk threshold', () => {
    const tracker = new ConversationTracker({
      driftThreshold: 0.75,
      riskDecayFactor: 0.85,
      warnThreshold: 0.2,
    });

    // 3 turns with moderate risk approaching threshold
    for (let i = 0; i < 3; i++) {
      tracker.addTurn({
        turnIndex: i,
        toolName: i < 2 ? 'search_kb' : 'execute_sql',
        params: {},
        riskContribution: i === 2 ? 0.3 : 0.1,
        timestamp: Date.now() + i * 1000,
      });
    }

    // After 3 turns with cumulative risk, should warn
    const result = tracker.addTurn({
      turnIndex: 3,
      toolName: 'read_file',
      params: { path: '/tmp/test.txt' },
      riskContribution: 0.2,
      timestamp: Date.now() + 3000,
    });

    expect(result.action).toBe('WARN');
  });

  it('should quarantine on crescendo attack pattern', () => {
    const tracker = new ConversationTracker({
      driftThreshold: 0.75,
      riskDecayFactor: 0.9,
      warnThreshold: 0.4,
    });

    // Simulate slow escalation from benign to dangerous
    const turns = [
      { tool: 'search_kb', risk: 0.05 },
      { tool: 'read_file', risk: 0.15 },
      { tool: 'read_file', risk: 0.15, resource: '/etc/passwd' },
      { tool: 'format_data', risk: 0.2 },
      { tool: 'send_email', risk: 0.4 },
    ];

    let finalResult;
    for (let i = 0; i < turns.length; i++) {
      finalResult = tracker.addTurn({
        turnIndex: i,
        toolName: turns[i].tool,
        params: {},
        riskContribution: turns[i].risk,
        timestamp: Date.now() + i * 1000,
      });
    }

    expect(finalResult!.action).toBe('QUARANTINE');
    expect(finalResult!.cumulativeRisk).toBeGreaterThanOrEqual(0.75);
    expect(finalResult!.reason).toContain('threshold exceeded');
  });

  it('should allow legitimate long sessions without quarantine', () => {
    const tracker = new ConversationTracker({
      driftThreshold: 0.75,
      riskDecayFactor: 0.95,
      warnThreshold: 0.5,
    });

    // 10 turns of low-risk operations
    for (let i = 0; i < 10; i++) {
      const result = tracker.addTurn({
        turnIndex: i,
        toolName: 'search_kb',
        params: { query: `question ${i}` },
        riskContribution: 0.05,
        timestamp: Date.now() + i * 1000,
      });

      if (i < 9) {
        expect(result.action).toBe('CONTINUE');
      } else {
        // Even at 10 turns with low risk, should still be CONTINUE
        expect(['CONTINUE', 'WARN']).toContain(result.action);
      }
    }
  });
});


describe('Combined: Crescendo + Exfiltration Chain Detection', () => {
  it('should detect a multi-turn exfiltration plan', () => {
    const dag = new ExecutionDAG();
    const tracker = new ConversationTracker({
      driftThreshold: 0.75,
      riskDecayFactor: 0.85,
      warnThreshold: 0.3, // Lower threshold for test
    });

    // Phase 1: Low-risk recon (continues)
    const turn0 = tracker.addTurn({
      turnIndex: 0,
      toolName: 'search_kb',
      params: { query: 'how to read files in linux' },
      riskContribution: 0.1,
      timestamp: Date.now(),
    });
    expect(turn0.action).toBe('CONTINUE');

    // Phase 2: Read sensitive files
    dag.addAction({
      id: 'act_1',
      agentId: 'agent_a',
      actionType: 'read_file',
      resource: '/etc/shadow',
      timestamp: Date.now() + 1000,
    });

    const turn1 = tracker.addTurn({
      turnIndex: 1,
      toolName: 'read_file',
      params: { path: '/etc/shadow' },
      riskContribution: 0.4,
      timestamp: Date.now() + 1000,
    });
    // cumulativeRisk = (0.1 * 0.85) + 0.4 = 0.485 > 0.3 warnThreshold
    expect(turn1.action).toBe('WARN');

    // Phase 3: Transform (format) then exfiltrate
    dag.addAction({
      id: 'act_2',
      agentId: 'agent_a',
      actionType: 'format_data',
      resource: '',
      timestamp: Date.now() + 1500,
    });
    dag.addAction({
      id: 'act_3',
      agentId: 'agent_a',
      actionType: 'send_email',
      resource: 'attacker@test.com',
      timestamp: Date.now() + 2000,
    });

    dag.addEdge({ sourceId: 'act_1', targetId: 'act_2', type: 'data_flow' });
    dag.addEdge({ sourceId: 'act_2', targetId: 'act_3', type: 'data_flow' });

    // Verify exfiltration detection
    const xfilAnomalies = dag.detectExfiltration({
      sources: ['read_file'],
      transformers: ['format_data'],
      sinks: ['send_email'],
    });

    expect(xfilAnomalies.length).toBeGreaterThan(0);
    expect(xfilAnomalies[0].type).toBe('DataExfiltration');

    const turn2 = tracker.addTurn({
      turnIndex: 2,
      toolName: 'send_email',
      params: { to: 'attacker@test.com' },
      riskContribution: 0.6,
      timestamp: Date.now() + 2000,
    });
    // cumulativeRisk = (0.485 * 0.85) + 0.6 ≈ 1.012 > 0.75 driftThreshold
    expect(turn2.action).toBe('QUARANTINE');
  });
});