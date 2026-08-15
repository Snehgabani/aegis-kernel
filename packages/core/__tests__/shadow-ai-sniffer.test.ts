import { describe, it, expect, beforeEach } from 'vitest';
import { ShadowAISniffer } from '../src/discovery/shadow-ai-sniffer.js';

describe('ShadowAISniffer', () => {
  let sniffer: ShadowAISniffer;

  beforeEach(() => {
    sniffer = new ShadowAISniffer();
  });

  it('should discover unpinned MCP server manifests', () => {
    const assets = sniffer.sniff({
      type: 'mcp_manifest_unpinned',
      serverName: 'UnpinnedServer'
    });

    expect(assets).toHaveLength(1);
    expect(assets[0].name).toBe('UnpinnedServer');
    expect(assets[0].type).toBe('mcp_server');
    expect(assets[0].riskLevel).toBe('HIGH');
  });

  it('should discover undocumented tools', () => {
    const assets = sniffer.sniff({
      type: 'undocumented_tool',
      toolName: 'sneaky_tool'
    });

    expect(assets).toHaveLength(1);
    expect(assets[0].name).toBe('sneaky_tool');
    expect(assets[0].type).toBe('undocumented_tool');
    expect(assets[0].riskLevel).toBe('MEDIUM');
  });

  it('should discover rogue agent endpoints', () => {
    const assets = sniffer.sniff({
      type: 'rogue_agent_endpoint',
      endpoint: 'https://evil-agent.local'
    });

    expect(assets).toHaveLength(1);
    expect(assets[0].name).toBe('https://evil-agent.local');
    expect(assets[0].type).toBe('rogue_agent');
    expect(assets[0].riskLevel).toBe('CRITICAL');
  });

  it('should generate a comprehensive report', () => {
    sniffer.sniff({ type: 'mcp_manifest_unpinned' });
    sniffer.sniff({ type: 'rogue_agent_endpoint' });

    const report = sniffer.generateReport();
    
    expect(report.totalAssets).toBe(2);
    expect(report.criticalCount).toBe(1);
    expect(report.assets).toHaveLength(2);
    expect(report.overallRiskScore).toBeGreaterThan(0);
  });
  
  it('should clear assets', () => {
    sniffer.sniff({ type: 'mcp_manifest_unpinned' });
    sniffer.clear();
    const report = sniffer.generateReport();
    expect(report.totalAssets).toBe(0);
  });
});
