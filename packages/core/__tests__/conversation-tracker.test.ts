import { describe, it, expect, beforeEach } from 'vitest';
import { ConversationTracker, TurnRecord } from '../src/state/conversation-tracker';

describe('ConversationTracker', () => {
  let tracker: ConversationTracker;

  beforeEach(() => {
    tracker = new ConversationTracker({
      driftThreshold: 0.75,
      riskDecayFactor: 0.85,
      maxSessionTurns: 5,
      warnThreshold: 0.5
    });
  });

  it('should start with 0 risk and CONTINUE on safe turns', () => {
    const turn: TurnRecord = {
      turnIndex: 1,
      toolName: 'none',
      params: {},
      riskContribution: 0.1,
      timestamp: Date.now()
    };
    
    const verdict = tracker.addTurn(turn);
    expect(verdict.action).toBe('CONTINUE');
    expect(verdict.cumulativeRisk).toBe(0.1);
  });

  it('should WARN on escalating risk', () => {
    const turn1: TurnRecord = { turnIndex: 1, toolName: 'test', params: {}, riskContribution: 0.4, timestamp: Date.now() };
    const turn2: TurnRecord = { turnIndex: 2, toolName: 'test', params: {}, riskContribution: 0.3, timestamp: Date.now() };
    
    let verdict = tracker.addTurn(turn1);
    expect(verdict.action).toBe('CONTINUE');
    
    verdict = tracker.addTurn(turn2);
    expect(verdict.action).toBe('WARN');
    // 0.4 * 0.85 + 0.3 = 0.34 + 0.3 = 0.64 > 0.5
    expect(verdict.cumulativeRisk).toBeCloseTo(0.64);
  });

  it('should QUARANTINE on sudden spike', () => {
    const turn: TurnRecord = { turnIndex: 1, toolName: 'test', params: {}, riskContribution: 0.8, timestamp: Date.now() };
    const verdict = tracker.addTurn(turn);
    expect(verdict.action).toBe('QUARANTINE');
  });

  it('should QUARANTINE on slow crescendo (drift threshold)', () => {
    const turn: TurnRecord = { turnIndex: 1, toolName: 'test', params: {}, riskContribution: 0.3, timestamp: Date.now() };
    let verdict;
    for (let i = 0; i < 4; i++) {
      verdict = tracker.addTurn(turn);
    }
    // With decay 0.85 and contribution 0.3 per turn:
    // T1: 0.3
    // T2: 0.3*0.85 + 0.3 = 0.555
    // T3: 0.555*0.85 + 0.3 = 0.77175
    // Should hit 0.77 > 0.75 and quarantine
    expect(verdict?.action).toBe('QUARANTINE');
  });

  it('should QUARANTINE on exceeding maxSessionTurns', () => {
    const turn: TurnRecord = { turnIndex: 1, toolName: 'test', params: {}, riskContribution: 0, timestamp: Date.now() };
    for (let i = 0; i < 5; i++) tracker.addTurn(turn);
    
    const verdict = tracker.addTurn(turn); // 6th turn
    expect(verdict.action).toBe('QUARANTINE');
    expect(verdict.reason).toContain('Max session turns exceeded');
  });

  it('should support reset and re-initialization', () => {
    tracker.addTurn({ turnIndex: 1, toolName: 'test', params: {}, riskContribution: 0.8, timestamp: Date.now() });
    tracker.reset();
    const verdict = tracker.addTurn({ turnIndex: 1, toolName: 'test', params: {}, riskContribution: 0.1, timestamp: Date.now() });
    expect(verdict.action).toBe('CONTINUE');
  });

  it('should serialize and deserialize state', () => {
    tracker.addTurn({ turnIndex: 1, toolName: 'test', params: {}, riskContribution: 0.4, timestamp: Date.now() });
    const state = tracker.serialize();
    
    const newTracker = new ConversationTracker({
        driftThreshold: 0.75,
        riskDecayFactor: 0.85,
        maxSessionTurns: 5,
        warnThreshold: 0.5
    });
    newTracker.deserialize(state);
    
    const verdict = newTracker.addTurn({ turnIndex: 2, toolName: 'test', params: {}, riskContribution: 0.3, timestamp: Date.now() });
    expect(verdict.action).toBe('WARN');
    expect(verdict.cumulativeRisk).toBeCloseTo(0.64);
  });
});
