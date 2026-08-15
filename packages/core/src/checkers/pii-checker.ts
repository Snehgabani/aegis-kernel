import type { AegisViolation, RegexConditionParams, ToolCall } from '../types.js';

// Pre-compiled high-recall regex patterns for PII, Secrets, and Compliance Invariants
export const DEFAULT_PII_PATTERNS = {
  CREDIT_CARD:
    /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/,
  US_SSN: /\b\d{3}-\d{2}-\d{4}\b/,
  OPENAI_API_KEY: /\b(?:sk-ant-api[0-9a-zA-Z_-]{15,}|sk-(?:proj-|live-)?[a-zA-Z0-9_-]{20,})\b/,
  GITHUB_TOKEN: /\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{20,}\b/,
  AWS_ACCESS_KEY: /\bAKIA[0-9A-Z]{16}\b/,
  STRIPE_KEY: /\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b/,
  GENERIC_BEARER: /\bBearer\s+[A-Za-z0-9\-_.]{15,}\b/,
  // Enterprise & Compliance Patterns (HIPAA, PCI-DSS, SOC 2)
  US_NPI: /\b[12]\d{9}\b/, // National Provider Identifier (10 digits starting with 1 or 2)
  US_DEA: /\b[A-Z]{2}\d{7}\b/, // Drug Enforcement Administration registration number
  ICD10_CODE: /\b[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b/, // Medical diagnostic code
  CREDIT_CARD_CVV: /\b(?:cvv|cvc|cvn|cid)\s*[:=]\s*\d{3,4}\b/i, // Card security code
  SENSITIVE_FILE_PATH: /(?:\/etc\/(?:shadow|passwd|sudoers)|\.ssh\/(?:id_rsa|authorized_keys)|\.env(?:\.[a-zA-Z0-9_-]+)?|\/proc\/self\/environ)/, // System traversal
};

export class PiiChecker {
  private compiledPatterns: Map<string, RegExp>;

  constructor() {
    this.compiledPatterns = new Map();
  }

  public evaluate(
    ruleId: string,
    packId: string,
    params: RegexConditionParams,
    toolCall: ToolCall
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];
    const textValues = this.collectStringValues(toolCall.params);

    for (const patternStr of params.patterns) {
      let regex = this.compiledPatterns.get(patternStr);
      if (!regex) {
        // Resolve either named pattern or custom regex string
        if (patternStr in DEFAULT_PII_PATTERNS) {
          regex = DEFAULT_PII_PATTERNS[patternStr as keyof typeof DEFAULT_PII_PATTERNS];
        } else {
          regex = new RegExp(patternStr, 'i');
        }
        this.compiledPatterns.set(patternStr, regex);
      }

      for (const text of textValues) {
        if (regex.test(text)) {
          const match = text.match(regex);
          const sanitizedMatch = match ? match[0].slice(0, 4) + '***' : '***';
          const severity = params.match_action === 'warn' ? 'warning' : 'critical';

          violations.push({
            ruleId,
            packId,
            severity,
            message: `Sensitive credential or PII pattern '${patternStr}' detected in tool arguments.`,
            suggestedFix: `Redact or parameterize sensitive tokens before invoking tool '${toolCall.tool}'.`,
            context: {
              pattern: patternStr,
              sample: sanitizedMatch,
            },
          });
          break; // Avoid duplicate violations per pattern
        }
      }
    }

    return violations;
  }

  private normalizeString(text: string): string {
    // Strip zero-width and invisible control characters used for regex evasion
    const stripped = text.replace(/[\u200B-\u200D\u2060\uFEFF\u00AD]/g, '');
    // Normalize unicode forms (NFKD)
    return stripped.normalize('NFKD');
  }

  private collectStringValues(obj: unknown, collected: string[] = []): string[] {
    if (typeof obj === 'string') {
      collected.push(obj);
      const normalized = this.normalizeString(obj);
      if (normalized !== obj) {
        collected.push(normalized);
      }
    } else if (Array.isArray(obj)) {
      for (const item of obj) {
        this.collectStringValues(item, collected);
      }
    } else if (obj !== null && typeof obj === 'object') {
      for (const val of Object.values(obj as Record<string, unknown>)) {
        this.collectStringValues(val, collected);
      }
    }
    return collected;
  }
}
