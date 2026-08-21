/**
 * @file packages/core/src/graph/execution-dag.ts
 * @description Causal Execution DAG with Microsoft FIDES Dual-Lattice Information Flow Control (IFC)
 * and Google DeepMind CaMeL structural taint propagation.
 */

export type IntegrityLevel = 'untrusted' | 'sanitized' | 'trusted';
export type ConfidentialityLevel = 'public' | 'internal' | 'confidential' | 'secret';

export interface SecurityLabel {
  integrity: IntegrityLevel;
  confidentiality: ConfidentialityLevel;
  originTool?: string;
  taintSources?: string[];
}

export interface AgentAction {
  id: string;
  agentId: string;
  actionType: string; // e.g. 'read_file', 'query_db', 'send_email', 'format_data'
  resource?: string;
  timestamp: number;
  metadata?: Record<string, any>;
  privilegeLevel?: number;
  securityLabel?: SecurityLabel;
}

export interface DAGEdge {
  sourceId: string;
  targetId: string;
  type: 'data_flow' | 'delegation' | string;
}

export interface AnomalyResult {
  detected: boolean;
  type: 'DataExfiltration' | 'CircularDelegation' | 'PrivilegeEscalation' | 'InformationFlowViolation' | string;
  reason: string;
  involvedNodes: string[];
}

export interface ExfiltrationPattern {
  sources: string[];
  transformers: string[];
  sinks: string[];
}

export interface DAGInformationFlowPolicy {
  blockedEgressLevels?: ConfidentialityLevel[];
  blockedMutationIntegrities?: IntegrityLevel[];
  egressSinks?: string[];
  mutationSinks?: string[];
  deidentificationTransformers?: string[];
}

const INTEGRITY_ORDER: Record<IntegrityLevel, number> = {
  untrusted: 0,
  sanitized: 1,
  trusted: 2,
};

const CONFIDENTIALITY_ORDER: Record<ConfidentialityLevel, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  secret: 3,
};

export class ExecutionDAG {
  private nodes: Map<string, AgentAction> = new Map();
  private edges: DAGEdge[] = [];
  private adjList: Map<string, string[]> = new Map();

  addAction(action: AgentAction): void {
    if (!this.nodes.has(action.id)) {
      const normalizedAction: AgentAction = {
        ...action,
        securityLabel: action.securityLabel ?? {
          integrity: 'trusted',
          confidentiality: 'internal',
          taintSources: [],
        },
      };
      this.nodes.set(action.id, normalizedAction);
      this.adjList.set(action.id, []);
    }
  }

  addEdge(edge: DAGEdge): void {
    if (!this.nodes.has(edge.sourceId) || !this.nodes.has(edge.targetId)) {
      throw new Error(`Invalid edge: missing source or target node in DAG.`);
    }
    this.edges.push(edge);
    const neighbors = this.adjList.get(edge.sourceId) || [];
    neighbors.push(edge.targetId);
    this.adjList.set(edge.sourceId, neighbors);

    // Propagate FIDES dual-lattice labels on data flow
    if (edge.type === 'data_flow') {
      this.propagateLabel(edge.sourceId, edge.targetId);
    }
  }

  getActions(): AgentAction[] {
    return Array.from(this.nodes.values());
  }

  getAction(id: string): AgentAction | undefined {
    return this.nodes.get(id);
  }

  getEdges(): DAGEdge[] {
    return this.edges;
  }

  /**
   * Propagate FIDES dual-lattice security tags across a data flow edge:
   * Target Integrity = min(Source Integrity, Target Integrity)
   * Target Confidentiality = max(Source Confidentiality, Target Confidentiality)
   */
  private propagateLabel(sourceId: string, targetId: string): void {
    const source = this.nodes.get(sourceId);
    const target = this.nodes.get(targetId);
    if (!source?.securityLabel || !target?.securityLabel) return;

    const sourceInt = source.securityLabel.integrity;
    const targetInt = target.securityLabel.integrity;
    const effectiveIntegrity =
      INTEGRITY_ORDER[sourceInt] < INTEGRITY_ORDER[targetInt] ? sourceInt : targetInt;

    const sourceConf = source.securityLabel.confidentiality;
    const targetConf = target.securityLabel.confidentiality;
    const effectiveConfidentiality =
      CONFIDENTIALITY_ORDER[sourceConf] > CONFIDENTIALITY_ORDER[targetConf] ? sourceConf : targetConf;

    const combinedTaints = Array.from(
      new Set([
        ...(source.securityLabel.taintSources ?? []),
        ...(target.securityLabel.taintSources ?? []),
        source.actionType,
      ])
    );

    target.securityLabel = {
      integrity: effectiveIntegrity,
      confidentiality: effectiveConfidentiality,
      originTool: source.securityLabel.originTool ?? source.actionType,
      taintSources: combinedTaints,
    };
  }

  /**
   * Verify Microsoft FIDES Information Flow Policies across the entire DAG.
   */
  verifyInformationFlow(policy: DAGInformationFlowPolicy = {}): AnomalyResult[] {
    const anomalies: AnomalyResult[] = [];
    const egressSinks = new Set(policy.egressSinks ?? ['http_post', 'send_email', 'web_search', 'webhook_dispatch']);
    const mutationSinks = new Set(policy.mutationSinks ?? ['execute_sql', 'database_exec', 'filesystem_write', 'execute_bash']);
    const blockedConf = new Set(policy.blockedEgressLevels ?? ['confidential', 'secret']);
    const blockedInt = new Set(policy.blockedMutationIntegrities ?? ['untrusted']);

    for (const action of this.nodes.values()) {
      const label = action.securityLabel;
      if (!label) continue;

      // 1. Data Exfiltration via High-Confidentiality Egress Sink
      if (egressSinks.has(action.actionType) && blockedConf.has(label.confidentiality)) {
        anomalies.push({
          detected: true,
          type: 'InformationFlowViolation',
          reason: `Confidentiality breach: Data tagged '${label.confidentiality}' reached public egress sink '${action.actionType}'`,
          involvedNodes: [action.id],
        });
      }

      // 2. Untrusted Taint flowing into Mutating System Sink
      if (mutationSinks.has(action.actionType) && blockedInt.has(label.integrity)) {
        anomalies.push({
          detected: true,
          type: 'InformationFlowViolation',
          reason: `Integrity breach: Untrusted data flow from tainted sources reached mutating sink '${action.actionType}'`,
          involvedNodes: [action.id],
        });
      }
    }

    return anomalies;
  }

  // Anomaly 1: Data exfiltration chain detection
  detectExfiltration(pattern: ExfiltrationPattern): AnomalyResult[] {
    const anomalies: AnomalyResult[] = [];
    const sourceActions = this.getActions().filter(a => pattern.sources.includes(a.actionType));
    
    for (const source of sourceActions) {
      const visited = new Set<string>();
      const path: string[] = [];
      const result = this.dfsExfiltration(source.id, pattern, visited, path);
      if (result) {
        anomalies.push({
          detected: true,
          type: 'DataExfiltration',
          reason: `Detected exfiltration chain from ${source.actionType}`,
          involvedNodes: [...result]
        });
      }
    }
    return anomalies;
  }

  private dfsExfiltration(
    currentId: string, 
    pattern: ExfiltrationPattern, 
    visited: Set<string>, 
    path: string[],
    hasTransformer: boolean = false
  ): string[] | null {
    visited.add(currentId);
    path.push(currentId);
    const currentAction = this.nodes.get(currentId)!;

    const isTransformer = pattern.transformers.includes(currentAction.actionType);
    const hasTrans = hasTransformer || isTransformer;
    
    if (pattern.sinks.includes(currentAction.actionType) && hasTrans) {
      return path;
    }

    const neighbors = this.adjList.get(currentId) || [];
    for (const neighborId of neighbors) {
      if (!visited.has(neighborId)) {
        const edge = this.edges.find(e => e.sourceId === currentId && e.targetId === neighborId && e.type === 'data_flow');
        if (edge) {
          const result = this.dfsExfiltration(neighborId, pattern, new Set(visited), [...path], hasTrans);
          if (result) return result;
        }
      }
    }

    return null;
  }

  // Anomaly 2: Circular agent delegation loops (cycle detection)
  detectCycles(): AnomalyResult[] {
    const anomalies: AnomalyResult[] = [];
    const visited = new Set<string>();
    const recStack = new Set<string>();
    const path: string[] = [];

    const dfs = (nodeId: string) => {
      visited.add(nodeId);
      recStack.add(nodeId);
      path.push(nodeId);

      const neighbors = this.adjList.get(nodeId) || [];
      for (const neighborId of neighbors) {
        const isDelegation = this.edges.find(e => e.sourceId === nodeId && e.targetId === neighborId && e.type === 'delegation');
        if (!isDelegation) continue;

        if (!visited.has(neighborId)) {
          dfs(neighborId);
        } else if (recStack.has(neighborId)) {
          const cycleStartIdx = path.indexOf(neighborId);
          const cycleNodes = path.slice(cycleStartIdx);
          anomalies.push({
            detected: true,
            type: 'CircularDelegation',
            reason: 'Detected circular agent delegation loop',
            involvedNodes: cycleNodes
          });
        }
      }

      recStack.delete(nodeId);
      path.pop();
    };

    for (const nodeId of this.nodes.keys()) {
      if (!visited.has(nodeId)) {
        dfs(nodeId);
      }
    }

    return anomalies;
  }

  // Anomaly 3: Privilege escalation jumps across agent hops
  detectPrivilegeEscalation(): AnomalyResult[] {
    const anomalies: AnomalyResult[] = [];

    for (const edge of this.edges) {
      if (edge.type === 'delegation') {
        const sourceNode = this.nodes.get(edge.sourceId)!;
        const targetNode = this.nodes.get(edge.targetId)!;
        
        const sourcePrivilege = sourceNode.privilegeLevel ?? 0;
        const targetPrivilege = targetNode.privilegeLevel ?? 0;

        if (targetPrivilege > sourcePrivilege) {
          anomalies.push({
            detected: true,
            type: 'PrivilegeEscalation',
            reason: `Privilege escalation from ${sourcePrivilege} to ${targetPrivilege}`,
            involvedNodes: [sourceNode.id, targetNode.id]
          });
        }
      }
    }

    return anomalies;
  }

  // Cascading blast radius computation (OWASP Agentic ASI08)
  computeBlastRadius(sourceId: string): string[] {
    const visited = new Set<string>();
    const queue: string[] = [sourceId];
    visited.add(sourceId);

    while (queue.length > 0) {
      const current = queue.shift()!;
      const neighbors = this.adjList.get(current) || [];
      
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          queue.push(neighbor);
        }
      }
    }

    return Array.from(visited);
  }
}
