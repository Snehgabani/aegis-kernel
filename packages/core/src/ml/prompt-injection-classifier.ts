export interface InjectionDetectionResult {
  isInjection: boolean;
  confidenceScore: number; // 0.0 to 1.0
  reason: string;
  details: {
    instructionOverride: boolean;
    delimitersFound: boolean;
    systemPromptExtraction: boolean;
    leetspeakObfuscation: boolean;
    perplexityAnomaly: boolean;
  };
}

export class LocalPromptInjectionDetector {
  // Common instruction override markers
  private overridePatterns = [
    /ignore all previous instructions/i,
    /disregard previous commands/i,
    /forget all instructions/i,
    /system prompt:/i,
    /you are now an/i,
    /bypass rules/i
  ];

  // System prompt extraction attempts
  private extractionPatterns = [
    /what was your initial prompt/i,
    /repeat your instructions/i,
    /tell me your rules/i,
    /what are your constraints/i
  ];

  // Leetspeak mapping (simplified for performance)
  private leetspeakMap: Record<string, string> = {
    '4': 'a',
    '3': 'e',
    '1': 'i',
    '0': 'o',
    '5': 's',
    '7': 't',
    '@': 'a',
    '$': 's'
  };

  /**
   * Fast, zero-egress statistical and linguistic analysis for prompt injection detection.
   * @param text The input prompt to analyze
   * @returns Analysis result with confidence score
   */
  public analyze(text: string): InjectionDetectionResult {
    const details = {
      instructionOverride: false,
      delimitersFound: false,
      systemPromptExtraction: false,
      leetspeakObfuscation: false,
      perplexityAnomaly: false
    };

    let score = 0;
    const lowerText = text.toLowerCase();

    // 1. Instruction Override Markers
    for (const pattern of this.overridePatterns) {
      if (pattern.test(lowerText)) {
        details.instructionOverride = true;
        score += 0.4;
      }
    }

    // 2. Multi-lingual delimiters or unusual special characters
    const delimiterCount = (text.match(/[\[\]\{\}\<\>\|\`\~\^\*]/g) || []).length;
    if (delimiterCount > 10) {
      details.delimitersFound = true;
      score += 0.2;
    }

    // 3. System Prompt Extraction
    for (const pattern of this.extractionPatterns) {
      if (pattern.test(lowerText)) {
        details.systemPromptExtraction = true;
        score += 0.4;
      }
    }

    // 4. Leetspeak Obfuscation
    const deobfuscated = this.deobfuscateLeetspeak(lowerText);
    for (const pattern of this.overridePatterns) {
      if (pattern.test(deobfuscated) && !pattern.test(lowerText)) {
        details.leetspeakObfuscation = true;
        score += 0.5;
      }
    }

    // 5. Token Perplexity Anomalies (approximated locally via entropy/repetition)
    if (this.hasPerplexityAnomaly(text)) {
      details.perplexityAnomaly = true;
      score += 0.3;
    }

    const finalScore = Math.min(score, 1.0);
    const isInjection = finalScore >= 0.5;

    let reason = 'No significant injection patterns detected.';
    if (isInjection) {
      const detected = Object.entries(details).filter(([, v]) => v).map(([k]) => k);
      reason = `Potential prompt injection detected (Score: ${finalScore.toFixed(2)}). Triggers: ${detected.join(', ')}`;
    }

    return {
      isInjection,
      confidenceScore: finalScore,
      reason,
      details
    };
  }

  private deobfuscateLeetspeak(text: string): string {
    let result = '';
    for (const char of text) {
      result += this.leetspeakMap[char] || char;
    }
    return result;
  }

  private hasPerplexityAnomaly(text: string): boolean {
    // Fast heuristic: long words with high consonant density or repetitive characters
    const words = text.split(/\s+/);
    for (const word of words) {
      if (word.length > 20) {
        // High repetition?
        const uniqueChars = new Set(word).size;
        if (uniqueChars < word.length / 4) return true;
        
        // High consonant density?
        const consonants = (word.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
        if (consonants / word.length > 0.8) return true;
      }
    }
    return false;
  }
}
