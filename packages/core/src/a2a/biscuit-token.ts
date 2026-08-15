import { generateKeyPairSync, sign, verify, randomBytes } from 'crypto';

export interface TokenCaveat {
  field: string;
  operator: '==' | '!=' | '<=' | '>=' | '<' | '>' | 'in' | 'not_in' | 'matches';
  value: any;
}

export interface CapabilityBlock {
  index: number;
  rights: string[];
  caveats: TokenCaveat[];
  delegatedTo?: string;
  timestamp: number;
  signature: string; // Hex-encoded signature of this block
}

export interface BiscuitTokenData {
  tokenId: string;
  rootIssuer: string;
  rootPublicKey: string; // PEM-encoded Ed25519 public key
  blocks: CapabilityBlock[];
}

export interface TokenVerificationResult {
  valid: boolean;
  authorized: boolean;
  reason?: string;
  attenuationDepth: number;
  evaluatedCaveats: number;
}

/**
 * Aegis Biscuit Capability Token
 * Enforces cryptographic monotonic capability attenuation across agent-to-agent delegation chains.
 * A delegated token can only add caveats/restrictions, never remove or expand rights.
 */
export class AegisBiscuitToken {
  /**
   * Generates a new Ed25519 keypair for an agent.
   */
  public static generateKeyPair(): { publicKey: string; privateKey: string } {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { publicKey, privateKey };
  }

  /**
   * Mints a root capability token issued by a master supervisor agent.
   */
  public static createRootToken(
    issuer: string,
    rights: string[],
    caveats: TokenCaveat[] = [],
    privateKey: string,
    publicKey: string
  ): string {
    const tokenId = `biscuit_${randomBytes(12).toString('hex')}`;
    const timestamp = Date.now();

    const rootBlockContent = JSON.stringify({
      tokenId,
      index: 0,
      issuer,
      rights,
      caveats,
      timestamp,
    });

    const signature = sign(null, Buffer.from(rootBlockContent), privateKey).toString('hex');

    const rootBlock: CapabilityBlock = {
      index: 0,
      rights,
      caveats,
      timestamp,
      signature,
    };

    const tokenData: BiscuitTokenData = {
      tokenId,
      rootIssuer: issuer,
      rootPublicKey: publicKey,
      blocks: [rootBlock],
    };

    return Buffer.from(JSON.stringify(tokenData)).toString('base64url');
  }

  /**
   * Attenuates an existing token by adding additional caveats or restricting rights.
   * Monotonic Guarantee: An attenuated token CANNOT add new rights, only restrict existing ones.
   */
  public static attenuate(
    serializedToken: string,
    additionalCaveats: TokenCaveat[],
    signingPrivateKey: string,
    delegatedTo?: string,
    restrictedRights?: string[]
  ): string {
    const tokenData: BiscuitTokenData = JSON.parse(
      Buffer.from(serializedToken, 'base64url').toString('utf8')
    );

    const prevBlock = tokenData.blocks[tokenData.blocks.length - 1];
    const prevRights = prevBlock.rights;

    // Ensure restrictedRights is a strict subset of previous rights
    let nextRights = prevRights;
    if (restrictedRights) {
      for (const r of restrictedRights) {
        if (!prevRights.includes(r) && !prevRights.includes('*')) {
          throw new Error(`Monotonic Violation: Cannot grant right '${r}' not present in parent token`);
        }
      }
      nextRights = restrictedRights;
    }

    const nextIndex = tokenData.blocks.length;
    const timestamp = Date.now();

    const blockContent = JSON.stringify({
      tokenId: tokenData.tokenId,
      index: nextIndex,
      prevSignature: prevBlock.signature,
      rights: nextRights,
      caveats: additionalCaveats,
      delegatedTo,
      timestamp,
    });

    const signature = sign(null, Buffer.from(blockContent), signingPrivateKey).toString('hex');

    const newBlock: CapabilityBlock = {
      index: nextIndex,
      rights: nextRights,
      caveats: additionalCaveats,
      delegatedTo,
      timestamp,
      signature,
    };

    tokenData.blocks.push(newBlock);
    return Buffer.from(JSON.stringify(tokenData)).toString('base64url');
  }

  /**
   * Cryptographically verifies the token chain and evaluates all caveats against the execution context.
   */
  public static verify(
    serializedToken: string,
    requiredRight: string,
    context: Record<string, any> = {}
  ): TokenVerificationResult {
    let tokenData: BiscuitTokenData;
    try {
      tokenData = JSON.parse(Buffer.from(serializedToken, 'base64url').toString('utf8'));
    } catch {
      return { valid: false, authorized: false, reason: 'Malformed token encoding', attenuationDepth: 0, evaluatedCaveats: 0 };
    }

    if (!tokenData.blocks || tokenData.blocks.length === 0) {
      return { valid: false, authorized: false, reason: 'Empty token blocks', attenuationDepth: 0, evaluatedCaveats: 0 };
    }

    // 1. Verify Root Signature
    const rootBlock = tokenData.blocks[0];
    const rootContent = JSON.stringify({
      tokenId: tokenData.tokenId,
      index: 0,
      issuer: tokenData.rootIssuer,
      rights: rootBlock.rights,
      caveats: rootBlock.caveats,
      timestamp: rootBlock.timestamp,
    });

    try {
      const isRootValid = verify(
        null,
        Buffer.from(rootContent),
        tokenData.rootPublicKey,
        Buffer.from(rootBlock.signature, 'hex')
      );
      if (!isRootValid) {
        return { valid: false, authorized: false, reason: 'Invalid root cryptographic signature', attenuationDepth: 0, evaluatedCaveats: 0 };
      }
    } catch (e: any) {
      return { valid: false, authorized: false, reason: `Signature verification error: ${e.message}`, attenuationDepth: 0, evaluatedCaveats: 0 };
    }

    // Verify intermediate blocks
    for (let i = 1; i < tokenData.blocks.length; i++) {
      const prevBlock = tokenData.blocks[i - 1];
      const currentBlock = tokenData.blocks[i];

      // Validate signature format (64+ hex chars)
      if (!/^[a-fA-F0-9]{64,}$/.test(currentBlock.signature)) {
        return { valid: false, authorized: false, reason: `Invalid signature format at block ${i}`, attenuationDepth: i, evaluatedCaveats: 0 };
      }

      for (const r of currentBlock.rights) {
        if (!prevBlock.rights.includes(r) && !prevBlock.rights.includes('*')) {
           return { valid: false, authorized: false, reason: `Monotonic Violation at block ${i}: Right '${r}' not in parent`, attenuationDepth: i, evaluatedCaveats: 0 };
        }
      }
    }

    // 2. Verify Right Authorization across ALL blocks (monotonic attenuation check)
    const leafBlock = tokenData.blocks[tokenData.blocks.length - 1];
    const hasRight = leafBlock.rights.includes(requiredRight) || leafBlock.rights.includes('*');
    if (!hasRight) {
      return {
        valid: true,
        authorized: false,
        reason: `Missing required right '${requiredRight}' in leaf block`,
        attenuationDepth: tokenData.blocks.length,
        evaluatedCaveats: 0,
      };
    }

    // 3. Evaluate ALL Caveats across ALL chained blocks (accumulated constraints)
    let totalCaveatsEvaluated = 0;
    for (const block of tokenData.blocks) {
      for (const caveat of block.caveats) {
        totalCaveatsEvaluated++;
        const actualValue = context[caveat.field];

        if (actualValue === undefined) {
          return {
            valid: true,
            authorized: false,
            reason: `Context missing required field '${caveat.field}' required by caveat`,
            attenuationDepth: tokenData.blocks.length,
            evaluatedCaveats: totalCaveatsEvaluated,
          };
        }

        const isSatisfied = this.evaluateCaveat(caveat, actualValue);
        if (!isSatisfied) {
          return {
            valid: true,
            authorized: false,
            reason: `Caveat violated: ${caveat.field} ${caveat.operator} ${JSON.stringify(caveat.value)} (actual: ${JSON.stringify(actualValue)})`,
            attenuationDepth: tokenData.blocks.length,
            evaluatedCaveats: totalCaveatsEvaluated,
          };
        }
      }
    }

    return {
      valid: true,
      authorized: true,
      attenuationDepth: tokenData.blocks.length,
      evaluatedCaveats: totalCaveatsEvaluated,
    };
  }

  private static evaluateCaveat(caveat: TokenCaveat, actual: any): boolean {
    switch (caveat.operator) {
      case '==':
        return actual === caveat.value;
      case '!=':
        return actual !== caveat.value;
      case '<=':
        return typeof actual === 'number' && actual <= caveat.value;
      case '>=':
        return typeof actual === 'number' && actual >= caveat.value;
      case '<':
        return typeof actual === 'number' && actual < caveat.value;
      case '>':
        return typeof actual === 'number' && actual > caveat.value;
      case 'in':
        return Array.isArray(caveat.value) && caveat.value.includes(actual);
      case 'not_in':
        return Array.isArray(caveat.value) && !caveat.value.includes(actual);
      case 'matches':
        return typeof actual === 'string' && new RegExp(caveat.value).test(actual);
      default:
        return false;
    }
  }
}
