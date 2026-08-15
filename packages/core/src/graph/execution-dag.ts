export interface AgentAction {
  id: string;
  agentId: string;
  actionType: string; // e.g. 'read_file', 'query_db', 'send_email', 'format_data'
  resource?: string;
  timestamp: number;
  metadata?: Record<string, any>;
  privilegeLevel?: number; // lower is more privileged or vice versa, lets say higher is more privileged
}

export interface DAGEdge {
  sourceId: string;
  targetId: string;
  type: string; // e.g. 'data_flow', 'delegation'
}

export interface AnomalyResult {
  detected: boolean;
  type: string;
  reason: string;
  involvedNodes: string[];
}

export interface ExfiltrationPattern {
  sources: string[];
  transformers: string[];
  sinks: string[];
}

export class ExecutionDAG {
  private nodes: Map<string, AgentAction> = new Map();
  private edges: DAGEdge[] = [];
  private adjList: Map<string, string[]> = new Map(); // targetId -> array of sourceIds? No, sourceId -> array of targetIds

  addAction(action: AgentAction): void {
    if (!this.nodes.has(action.id)) {
      this.nodes.set(action.id, action);
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
  }

  getActions(): AgentAction[] {
    return Array.from(this.nodes.values());
  }

  getEdges(): DAGEdge[] {
    return this.edges;
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
        // Find if edge is data flow
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
        // only care about delegation
        const isDelegation = this.edges.find(e => e.sourceId === nodeId && e.targetId === neighborId && e.type === 'delegation');
        if (!isDelegation) continue;

        if (!visited.has(neighborId)) {
          dfs(neighborId);
        } else if (recStack.has(neighborId)) {
          // cycle detected
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
