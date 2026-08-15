/**
 * @file packages/core/src/hitl/escalation.ts
 * @description Human-in-the-Loop (HITL) Interactive Escalation & Ticket Clearance Engine.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export interface HITLEscalationConfig {
  ticketTtlSeconds?: number;
  signingSecret?: string;
}

export interface EscalationRequest {
  agentId: string;
  toolName: string;
  params: Record<string, any>;
  reason: string;
  metadata?: Record<string, any>;
}

export interface EscalationTicket {
  ticketId: string;
  agentId: string;
  toolName: string;
  paramsHash: string;
  paramsSummary: string;
  reason: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
  createdAt: number;
  expiresAt: number;
  signature: string;
  resolvedAt?: number;
  resolvedBy?: string;
  resolutionReason?: string;
}

export interface TicketResolution {
  decision: 'APPROVED' | 'REJECTED';
  approver: string;
  reason?: string;
  signature: string;
}

export class HITLEscalationManager {
  private tickets: Map<string, EscalationTicket> = new Map();
  private ttlSeconds: number;
  private secret: string;

  constructor(config: HITLEscalationConfig = {}) {
    this.ttlSeconds = config.ticketTtlSeconds ?? 300; // 5 minutes default
    this.secret = config.signingSecret ?? 'aegis-default-hitl-signing-key';
  }

  /**
   * Generates a cryptographically signed human approval ticket for an escalated action.
   */
  public createTicket(request: EscalationRequest): EscalationTicket {
    const ticketId = `hitl-${Date.now()}-${randomBytes(4).toString('hex')}`;
    const createdAt = Date.now();
    const expiresAt = createdAt + this.ttlSeconds * 1000;

    const paramsStr = JSON.stringify(request.params);
    const paramsHash = createHash('sha256').update(paramsStr).digest('hex');
    const paramsSummary = paramsStr.length > 200 ? `${paramsStr.substring(0, 197)}...` : paramsStr;

    const signaturePayload = `${ticketId}:${request.agentId}:${request.toolName}:${paramsHash}:${expiresAt}`;
    const signature = createHmac('sha256', this.secret).update(signaturePayload).digest('hex');

    const ticket: EscalationTicket = {
      ticketId,
      agentId: request.agentId,
      toolName: request.toolName,
      paramsHash,
      paramsSummary,
      reason: request.reason,
      status: 'PENDING',
      createdAt,
      expiresAt,
      signature
    };

    this.tickets.set(ticketId, ticket);
    return ticket;
  }

  /**
   * Retrieves an active ticket by ID and checks for expiration.
   */
  public getTicket(ticketId: string): EscalationTicket | null {
    const ticket = this.tickets.get(ticketId);
    if (!ticket) return null;

    if (ticket.status === 'PENDING' && Date.now() > ticket.expiresAt) {
      ticket.status = 'EXPIRED';
    }

    return ticket;
  }

  /**
   * Resolves a pending ticket (Approve or Reject).
   */
  public resolveTicket(
    ticketId: string,
    resolution: TicketResolution
  ): { success: boolean; ticket?: EscalationTicket; error?: string } {
    const ticket = this.getTicket(ticketId);
    if (!ticket) {
      return { success: false, error: 'Ticket not found' };
    }

    if (ticket.status !== 'PENDING') {
      return { success: false, error: `Ticket cannot be resolved; current status is ${ticket.status}` };
    }

    const expectedSignaturePayload = `${ticket.ticketId}:${ticket.agentId}:${ticket.toolName}:${ticket.paramsHash}:${ticket.expiresAt}`;
    const expectedSignature = createHmac('sha256', this.secret).update(expectedSignaturePayload).digest('hex');

    try {
      const providedSigBuffer = Buffer.from(resolution.signature || '', 'hex');
      const expectedSigBuffer = Buffer.from(expectedSignature, 'hex');

      if (providedSigBuffer.length !== expectedSigBuffer.length || !timingSafeEqual(providedSigBuffer, expectedSigBuffer)) {
        return { success: false, error: 'Invalid ticket signature' };
      }
    } catch (e) {
      return { success: false, error: 'Invalid ticket signature format' };
    }

    ticket.status = resolution.decision;
    ticket.resolvedAt = Date.now();
    ticket.resolvedBy = resolution.approver;
    ticket.resolutionReason = resolution.reason ?? 'No explanation provided';

    return { success: true, ticket };
  }

  /**
   * Generates a formatted Slack Interactive Approval Block payload.
   */
  public formatSlackApprovalCard(ticket: EscalationTicket): Record<string, any> {
    return {
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: '🛡️ Aegis Security Escalation: Approval Required',
            emoji: true
          }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Agent ID:*\n\`${ticket.agentId}\`` },
            { type: 'mrkdwn', text: `*Tool:* \`${ticket.toolName}\`` },
            { type: 'mrkdwn', text: `*Ticket ID:*\n\`${ticket.ticketId}\`` },
            { type: 'mrkdwn', text: `*Expires In:*\n${Math.round((ticket.expiresAt - Date.now()) / 1000)}s` }
          ]
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Escalation Reason:*\n${ticket.reason}\n\n*Parameters:*\n\`\`\`json\n${ticket.paramsSummary}\n\`\`\``
          }
        },
        {
          type: 'actions',
          elements: [
            {
              type: 'button',
              text: { type: 'plain_text', text: '✅ Approve Execution', emoji: true },
              style: 'primary',
              value: ticket.ticketId,
              action_id: 'aegis_hitl_approve'
            },
            {
              type: 'button',
              text: { type: 'plain_text', text: '🚫 Reject & Block', emoji: true },
              style: 'danger',
              value: ticket.ticketId,
              action_id: 'aegis_hitl_reject'
            }
          ]
        }
      ]
    };
  }
}
