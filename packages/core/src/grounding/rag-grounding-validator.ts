export interface GroundingCheckOptions {
  requireExactMatch?: boolean;
  minLexicalOverlap?: number;
  entityCheckEnabled?: boolean;
}

export interface GroundingVerdict {
  isGrounded: boolean;
  containmentScore: number;
  entityAttributionScore: number;
  lexicalOverlapScore: number;
  hallucinatedFacts: string[];
  reason: string;
}

export class RAGGroundingValidator {
  
  /**
   * Verifies that the LLM output is grounded in the provided reference context.
   * @param output The generated output to verify
   * @param referenceContext Array of reference documents/chunks
   * @param options Grounding check configuration
   */
  public checkGrounding(
    output: string,
    referenceContext: string[],
    options: GroundingCheckOptions = {}
  ): GroundingVerdict {
    const minOverlap = options.minLexicalOverlap ?? 0.3;
    const combinedContext = referenceContext.join('\n').toLowerCase();
    const lowerOutput = output.toLowerCase();

    // 1. N-gram lexical overlap
    const outputTokens = this.tokenize(lowerOutput);
    const contextTokens = new Set(this.tokenize(combinedContext));
    
    let overlapCount = 0;
    for (const token of outputTokens) {
      if (contextTokens.has(token)) {
        overlapCount++;
      }
    }
    
    const lexicalOverlapScore = outputTokens.length > 0 
      ? overlapCount / outputTokens.length 
      : 1.0;

    // 2. Entity attribution (simplified: finding capitalized words/phrases)
    let entityAttributionScore = 1.0;
    const hallucinatedFacts: string[] = [];
    
    if (options.entityCheckEnabled !== false) {
      const outputEntities = this.extractEntities(output);
      let matchedEntities = 0;
      
      for (const entity of outputEntities) {
        if (combinedContext.includes(entity.toLowerCase())) {
          matchedEntities++;
        } else {
          hallucinatedFacts.push(`Entity '${entity}' not found in context`);
        }
      }
      
      if (outputEntities.length > 0) {
        entityAttributionScore = matchedEntities / outputEntities.length;
      }
    }

    // 3. Claim containment (simplified heuristic combining scores)
    const containmentScore = (lexicalOverlapScore + entityAttributionScore) / 2;

    const isGrounded = containmentScore >= minOverlap && 
      (!options.requireExactMatch || containmentScore > 0.8) &&
      hallucinatedFacts.length === 0;

    let reason = isGrounded 
      ? 'Output is well-grounded in the reference context.'
      : 'Output contains ungrounded claims or hallucinations.';

    return {
      isGrounded,
      containmentScore,
      entityAttributionScore,
      lexicalOverlapScore,
      hallucinatedFacts,
      reason
    };
  }

  private tokenize(text: string): string[] {
    return text.split(/[\s,.-]+/).filter(t => t.length > 2);
  }

  private extractEntities(text: string): string[] {
    // Naive entity extraction: words starting with capital letters
    const matches = text.match(/\b[A-Z][a-z]+\b/g) || [];
    // Filter out common sentence starters (very naive)
    return Array.from(new Set(matches)).filter(e => e.length > 1);
  }
}
