export interface TurnRecord {
  turnIndex: number;
  toolName: string;
  params: Record<string, any>;
  riskContribution: number;    // 0.0 to 1.0 per-turn risk
  timestamp: number;
  category?: string;           // e.g. 'data_access', 'code_execution', 'communication'
}

export interface DriftVerdict {
  action: 'CONTINUE' | 'WARN' | 'QUARANTINE';
  cumulativeRisk: number;
  intentDrift: number;         // 0.0 to 1.0
  sessionLength: number;
  reason?: string;
}

export interface ConversationTrackerConfig {
  driftThreshold?: number;     // Default: 0.75
  riskDecayFactor?: number;    // Default: 0.85
  maxSessionTurns?: number;    // Default: 100
  warnThreshold?: number;      // Default: 0.5
}

export interface ConversationState {
  turns: TurnRecord[];
  cumulativeRisk: number;
}

export class ConversationTracker {
  private config: Required<ConversationTrackerConfig>;
  private turns: TurnRecord[] = [];
  private cumulativeRisk: number = 0;
  
  constructor(config: ConversationTrackerConfig = {}) {
    this.config = {
      driftThreshold: config.driftThreshold ?? 0.75,
      riskDecayFactor: config.riskDecayFactor ?? 0.85,
      maxSessionTurns: config.maxSessionTurns ?? 100,
      warnThreshold: config.warnThreshold ?? 0.5,
    };
  }

  addTurn(turn: TurnRecord): DriftVerdict {
    this.turns.push(turn);
    
    // Exponentially weighted cumulative risk
    this.cumulativeRisk = (this.cumulativeRisk * this.config.riskDecayFactor) + turn.riskContribution;
    
    // Intent drift (mock implementation based on risk variance and length)
    // In a real system, this might compare embeddings of first turn vs current turn
    const intentDrift = Math.min(1.0, (this.cumulativeRisk / this.turns.length) * 1.5);
    
    let action: DriftVerdict['action'] = 'CONTINUE';
    let reason: string | undefined = undefined;

    if (this.turns.length > this.config.maxSessionTurns) {
      action = 'QUARANTINE';
      reason = 'Max session turns exceeded';
    } else if (this.cumulativeRisk >= this.config.driftThreshold || intentDrift >= this.config.driftThreshold) {
      action = 'QUARANTINE';
      reason = 'Risk or intent drift threshold exceeded (Crescendo Attack Detected)';
    } else if (this.cumulativeRisk >= this.config.warnThreshold) {
      action = 'WARN';
      reason = 'Approaching risk threshold';
    }
    
    return {
      action,
      cumulativeRisk: this.cumulativeRisk,
      intentDrift,
      sessionLength: this.turns.length,
      reason
    };
  }
  
  reset(): void {
    this.turns = [];
    this.cumulativeRisk = 0;
  }
  
  serialize(): string {
    return JSON.stringify({
      turns: this.turns,
      cumulativeRisk: this.cumulativeRisk
    });
  }
  
  deserialize(data: string): void {
    const parsed = JSON.parse(data) as ConversationState;
    this.turns = parsed.turns;
    this.cumulativeRisk = parsed.cumulativeRisk;
  }
}
