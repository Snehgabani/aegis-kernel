export type RiskClassification = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface DiscoveredAIAsset {
  id: string;
  name: string;
  type: 'mcp_server' | 'rogue_agent' | 'undocumented_tool' | 'network_endpoint';
  riskLevel: RiskClassification;
  mitreAtlasTags: string[];
  complianceExposure: number; // 0.0 to 1.0
  details: Record<string, any>;
  discoveredAt: Date;
}

export interface ShadowAIReport {
  timestamp: Date;
  totalAssets: number;
  criticalCount: number;
  assets: DiscoveredAIAsset[];
  overallRiskScore: number;
}

export class ShadowAISniffer {
  private assets: Map<string, DiscoveredAIAsset> = new Map();

  /**
   * Inspects a given manifest, activity log, or system snapshot for shadow AI assets.
   */
  public sniff(activityData: any): DiscoveredAIAsset[] {
    const discovered: DiscoveredAIAsset[] = [];

    // Simulate inspection of network/process activity, unpinned MCP servers, etc.
    if (activityData?.type === 'mcp_manifest_unpinned') {
      const asset: DiscoveredAIAsset = {
        id: `asset_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
        name: activityData.serverName || 'Unknown Server',
        type: 'mcp_server',
        riskLevel: 'HIGH',
        mitreAtlasTags: ['AML.T0005', 'AML.T0007'], // Example MITRE ATLAS tags
        complianceExposure: 0.8,
        details: { reason: 'Unpinned manifest version detected' },
        discoveredAt: new Date()
      };
      discovered.push(asset);
    }

    if (activityData?.type === 'undocumented_tool') {
        const asset: DiscoveredAIAsset = {
          id: `asset_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
          name: activityData.toolName || 'Unknown Tool',
          type: 'undocumented_tool',
          riskLevel: 'MEDIUM',
          mitreAtlasTags: ['AML.T0002'],
          complianceExposure: 0.5,
          details: { reason: 'Tool definition not found in registry' },
          discoveredAt: new Date()
        };
        discovered.push(asset);
    }
    
    if (activityData?.type === 'rogue_agent_endpoint') {
        const asset: DiscoveredAIAsset = {
            id: `asset_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
            name: activityData.endpoint || 'Unknown Endpoint',
            type: 'rogue_agent',
            riskLevel: 'CRITICAL',
            mitreAtlasTags: ['AML.T0016', 'AML.T0017'],
            complianceExposure: 0.95,
            details: { reason: 'Unverified external agent connection' },
            discoveredAt: new Date()
          };
          discovered.push(asset);
    }

    discovered.forEach(a => this.assets.set(a.id, a));
    return discovered;
  }

  /**
   * Generates a comprehensive report of all discovered shadow AI assets.
   */
  public generateReport(): ShadowAIReport {
    const assetList = Array.from(this.assets.values());
    const criticalCount = assetList.filter(a => a.riskLevel === 'CRITICAL').length;
    
    let overallRiskScore = 0;
    if (assetList.length > 0) {
      const sum = assetList.reduce((acc, curr) => acc + curr.complianceExposure, 0);
      overallRiskScore = sum / assetList.length;
    }

    return {
      timestamp: new Date(),
      totalAssets: assetList.length,
      criticalCount,
      assets: assetList,
      overallRiskScore
    };
  }

  public clear(): void {
      this.assets.clear();
  }
}
