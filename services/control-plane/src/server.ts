import http from 'http';
import {
  computeEventChainMerkleRoot,
  generateComplianceDossier,
  formatStixTaxiiIndicator,
  AegisEvent
} from '@aegis-kernel/core';
import { CloudMarketplaceMeter } from './metering/marketplace-metering.js';

export interface ControlPlaneConfig {
  port?: number;
  host?: string;
  enableMarketplaceMetering?: boolean;
}

export class AegisControlPlaneServer {
  private server: http.Server | null = null;
  private policies: Map<string, any[]> = new Map();
  private auditEvents: Map<string, AegisEvent[]> = new Map();
  private meter: CloudMarketplaceMeter;

  constructor() {
    this.meter = new CloudMarketplaceMeter();
    this.initializeDefaultPolicies();
  }

  private initializeDefaultPolicies(): void {
    this.policies.set('default', [
      {
        id: 'pol_enterprise_core',
        statements: [
          { effect: 'permit', principal: '*', action: 'query', resource: '*' },
          { effect: 'forbid', principal: '*', action: 'drop_database', resource: '*' }
        ]
      }
    ]);
  }

  public registerTenantPolicy(tenantId: string, policy: any): void {
    const existing = this.policies.get(tenantId) || [];
    existing.push(policy);
    this.policies.set(tenantId, existing);
  }

  public ingestAuditEvent(tenantId: string, event: AegisEvent): { eventId: string; merkleRoot: string } {
    const events = this.auditEvents.get(tenantId) || [];
    events.push(event);
    this.auditEvents.set(tenantId, events);

    // Record usage for cloud marketplace billing
    this.meter.recordUsage(tenantId, 'ToolCallExecutionUnits', 1);

    const merkleRoot = computeEventChainMerkleRoot(events);

    return {
      eventId: event.id,
      merkleRoot,
    };
  }

  public getTenantDossier(tenantId: string): any {
    const events = this.auditEvents.get(tenantId) || [];
    return generateComplianceDossier(events);
  }

  public getStixThreatFeed(tenantId: string): any[] {
    const events = this.auditEvents.get(tenantId) || [];
    const blockedEvents = events.filter(e => e.verdict === 'BLOCKED');
    return blockedEvents.map(e => formatStixTaxiiIndicator(e)).filter(Boolean);
  }

  public getMarketplaceMeter(): CloudMarketplaceMeter {
    return this.meter;
  }

  /**
   * Dispatches an HTTP request handler for the control plane API.
   */
  public handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;
    const method = req.method;

    res.setHeader('Content-Type', 'application/json');

    // 1. Health Check
    if (pathname === '/health' && method === 'GET') {
      res.writeHead(200);
      res.end(JSON.stringify({ status: 'HEALTHY', service: 'aegis-control-plane', timestamp: new Date().toISOString() }));
      return;
    }

    // 2. Policy Distribution Endpoint: GET /v1/policies?tenantId=xxx
    if (pathname === '/v1/policies' && method === 'GET') {
      const tenantId = url.searchParams.get('tenantId') || 'default';
      const tenantPolicies = this.policies.get(tenantId) || this.policies.get('default') || [];
      res.writeHead(200);
      res.end(JSON.stringify({ tenantId, policies: tenantPolicies }));
      return;
    }

    // 3. Merkle Compliance Dossier: GET /v1/compliance/dossier?tenantId=xxx
    if (pathname === '/v1/compliance/dossier' && method === 'GET') {
      const tenantId = url.searchParams.get('tenantId') || 'default';
      const dossier = this.getTenantDossier(tenantId);
      res.writeHead(200);
      res.end(JSON.stringify(dossier));
      return;
    }

    // 4. STIX 2.1 CTI Threat Intel Stream: GET /v1/threat-intel/stix?tenantId=xxx
    if (pathname === '/v1/threat-intel/stix' && method === 'GET') {
      const tenantId = url.searchParams.get('tenantId') || 'default';
      const stixFeed = this.getStixThreatFeed(tenantId);
      res.writeHead(200);
      res.end(JSON.stringify({ tenantId, count: stixFeed.length, stixBundle: stixFeed }));
      return;
    }

    // Default 404
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  }

  public listen(port: number = 8080): Promise<void> {
    return new Promise((resolve) => {
      this.server = http.createServer((req, res) => this.handleRequest(req, res));
      this.server.listen(port, () => resolve());
    });
  }

  public close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}
