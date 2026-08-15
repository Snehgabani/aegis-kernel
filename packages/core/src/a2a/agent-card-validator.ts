import { verify } from 'crypto';

export interface AgentSkill {
  id: string;
  name: string;
  description: string;
  tags?: string[];
  inputSchema?: Record<string, any>;
  outputSchema?: Record<string, any>;
}

export interface AgentCard {
  id: string;
  name: string;
  version: string;
  description: string;
  organization: string;
  securityLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  publicKey: string; // PEM-encoded Ed25519 or RSA public key
  endpoint?: string;
  skills: AgentSkill[];
  signatures: {
    issuer: string;
    signature: string; // Hex signature of the agent card content
  };
}

export interface AgentCardValidationResult {
  valid: boolean;
  trusted: boolean;
  errors: string[];
  securityLevel: string;
  skillsCount: number;
}

/**
 * Validates Google / Linux Foundation A2A Agent Cards
 * Ensures agent identity, capabilities, and security boundaries are cryptographically verified.
 */
export class AgentCardValidator {
  private trustedOrgs: Set<string>;

  constructor(trustedOrgs: string[] = []) {
    this.trustedOrgs = new Set(trustedOrgs);
  }

  public addTrustedOrg(org: string): void {
    this.trustedOrgs.add(org);
  }

  public validateCard(card: AgentCard): AgentCardValidationResult {
    const errors: string[] = [];

    // 1. Structure validation
    if (!card.id || typeof card.id !== 'string') errors.push('Missing or invalid agent ID');
    if (!card.name || typeof card.name !== 'string') errors.push('Missing or invalid agent name');
    if (!card.version) errors.push('Missing agent version');
    if (!card.publicKey) errors.push('Missing agent public key');
    if (!card.signatures || !card.signatures.signature) errors.push('Missing cryptographic signature');

    if (errors.length > 0) {
      return {
        valid: false,
        trusted: false,
        errors,
        securityLevel: card.securityLevel || 'UNKNOWN',
        skillsCount: card.skills?.length || 0,
      };
    }

    // 2. Cryptographic Signature Verification
    const payloadToVerify = JSON.stringify({
      id: card.id,
      name: card.name,
      version: card.version,
      description: card.description,
      organization: card.organization,
      securityLevel: card.securityLevel,
      skills: card.skills,
    });

    try {
      const isSignatureValid = verify(
        null,
        Buffer.from(payloadToVerify),
        card.publicKey,
        Buffer.from(card.signatures.signature, 'hex')
      );

      if (!isSignatureValid) {
        errors.push('Cryptographic signature mismatch on Agent Card');
      }
    } catch (e: any) {
      errors.push(`Signature verification failed: ${e.message}`);
    }

    // 3. Trust validation
    const isTrusted = this.trustedOrgs.size === 0 || this.trustedOrgs.has(card.organization);
    if (!isTrusted) {
      errors.push(`Untrusted organization: ${card.organization}`);
    }

    return {
      valid: errors.length === 0,
      trusted: isTrusted && errors.length === 0,
      errors,
      securityLevel: card.securityLevel,
      skillsCount: card.skills.length,
    };
  }
}
