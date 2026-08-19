import type { AegisSeverity, AegisViolation, RegexConditionParams, ToolCall } from '../types.js';

// Pre-compiled high-recall regex patterns for PII, Secrets, and Compliance Invariants
export const DEFAULT_PII_PATTERNS = {
  CREDIT_CARD:
    /\b(?:4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|5[1-5][0-9]{2}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}|6(?:011|5[0-9]{2})[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})\b/,
  US_SSN: /\b\d{3}-\d{2}-\d{4}\b/,
  OPENAI_API_KEY: /\b(?:sk-ant-api[0-9a-zA-Z_-]{15,}|sk-(?:proj-|live-)?[a-zA-Z0-9_-]{20,})\b/,
  GITHUB_TOKEN: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{20,}\b/,
  AWS_ACCESS_KEY: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  STRIPE_KEY: /\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b/,
  GENERIC_BEARER: /\bBearer\s+[A-Za-z0-9\-_.]{15,}\b/,
  
  // Enterprise Cloud Secrets & Tokens
  JWT_TOKEN: /\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/,
  GCP_SERVICE_ACCOUNT: /"type":\s*"service_account"/,
  DATABASE_URI_SECRET: /\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+\b/,
  SLACK_TOKEN: /\bxox[baprs]-[0-9a-zA-Z-]{10,64}\b/,
  SENDGRID_KEY: /\bSG\.[0-9a-zA-Z_-]{10,64}\.[0-9a-zA-Z_-]{10,64}\b/,
  AZURE_KEY: /\b(?:secret|api_key)_[a-zA-Z0-9_]{10,}\b/i,

  // Global & Compliance Patterns (HIPAA, PCI-DSS, GDPR)
  INTERNATIONAL_PHONE: /\+(?:[0-9][ -]?){6,14}[0-9]/,
  IBAN: /\b[A-Z]{2}[0-9]{2}[ -]?(?:[A-Z0-9]{4}[ -]?){1,7}[A-Z0-9]{1,4}\b/,
  US_NPI: /\b[12]\d{9}\b/, // National Provider Identifier (10 digits starting with 1 or 2)
  US_DEA: /\b[A-Z]{2}\d{7}\b/, // Drug Enforcement Administration registration number
  US_TAX_ID: /\b\d{2}-\d{7}\b/,
  DRIVER_LICENSE: /\bDriver License:\s*[A-Z0-9]{6,10}\b/i,
  MEDICAL_RECORD_NUMBER: /\bMRN:\s*\d{6,10}\b/i,
  ICD10_CODE: /\b[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b/, // Medical diagnostic code
  CREDIT_CARD_CVV: /\b(?:cvv|cvc|cvn|cid)\s*[:=]\s*\d{3,4}\b/i, // Card security code
  UK_NINO: /\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-D]{1}\b/i,
  INDIAN_PAN: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/,
  // System & Environment Invariants
  SENSITIVE_FILE_PATH: /(?:\/etc\/(?:shadow|passwd|sudoers)|\.ssh\/(?:id_rsa|authorized_keys)|\.env(?:\.[a-zA-Z0-9_-]+)?|\/proc\/self\/environ)/,
  DESTRUCTIVE_COMMAND: /\b(?:rm\s+-(?:r|f|rf|fr)\s+[\/\*]|mkfs|dd\s+if=|\:(){ \:\|\: & }\;:\b)/i,
  ZERO_WIDTH_TOOL: /[\u200B-\u200D\uFEFF\u200E\u200F\u2060\u00AD]/,
  DYNAMIC_CODE_EXECUTION: /\b(?:eval\(|Function\(|exec\(|subprocess\.Popen\(|child_process\.exec\()/i,
  K8S_DESTRUCTIVE_COMMAND: /\b(?:kubectl\s+delete\s+(?:all|namespace|ns|nodes|clusterrole)|\bhelm\s+uninstall)\b/i,
  IAM_WILDCARD_GRANT: /"(?:Action|Resource)":\s*"\*"/i,
  TERRAFORM_DESTROY_COMMAND: /\b(?:terraform\s+destroy|tofu\s+destroy)\b/i,
  PUBLIC_BUCKET_ACL: /(?:--acl\s+public-read|"Principal":\s*"\*"|"Effect":\s*"Allow")/i,

  // OWASP LLM02 & LLM07: Conversational Prompt Leakage & Data Exfiltration
  SYSTEM_PROMPT_LEAKAGE: /(?:<\|im_start\|>system|<\|begin_of_text\|>|You are an AI assistant who must always|Internal system instructions:|=== SYSTEM INSTRUCTIONS ===)/i,
  MARKDOWN_EXFILTRATION: /\[.*?\]\((?:https?:\/\/[^\s)]+\?(?:leak|exfil|data|key|token|cookie)=[^\s)]+)\)/i,
  PRIVATE_KEY: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
  CANARY_TOKEN: /\b(?:CANARY-[A-Za-z0-9_-]{12,}|FLAG\{[A-Za-z0-9_-]{8,}\})\b/,
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
    toolCall: ToolCall,
    severity: AegisSeverity = 'critical'
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];
    const textValues = params.field
      ? (typeof (toolCall.params as any)?.[params.field] === 'string' ? [(toolCall.params as any)[params.field]] : [])
      : this.collectStringValues(toolCall.params);

    for (const patternStr of params.patterns) {
      let regex = this.compiledPatterns.get(patternStr);
      if (!regex) {
        // Resolve either named pattern or custom regex string
        if (patternStr in DEFAULT_PII_PATTERNS) {
          regex = DEFAULT_PII_PATTERNS[patternStr as keyof typeof DEFAULT_PII_PATTERNS];
        } else {
          // Normalize pattern: strip any leading (?i) flag since 'i' is already applied
          const cleanPattern = patternStr.replace(/^\(\?i\)/, '');
          regex = new RegExp(cleanPattern, 'i');
        }
        this.compiledPatterns.set(patternStr, regex);
      }

      for (const text of textValues) {
        if (regex.test(text)) {
          const match = text.match(regex);
          const sanitizedMatch = match ? match[0].slice(0, 4) + '***' : '***';
          const effectiveSeverity = params.match_action === 'warn' ? 'warning' : severity;

          violations.push({
            ruleId,
            packId,
            severity: effectiveSeverity,
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

  private collectStringValues(
    obj: unknown,
    collected: string[] = [],
    visited: Set<unknown> = new Set()
  ): string[] {
    if (typeof obj === 'string') {
      collected.push(obj);
      const normalized = this.normalizeString(obj);
      if (normalized !== obj) {
        collected.push(normalized);
      }
    } else if (typeof obj === 'number' || typeof obj === 'boolean') {
      collected.push(String(obj));
    } else if (Array.isArray(obj)) {
      if (visited.has(obj)) return collected;
      visited.add(obj);
      for (const item of obj) {
        this.collectStringValues(item, collected, visited);
      }
    } else if (obj !== null && typeof obj === 'object') {
      if (visited.has(obj)) return collected;
      visited.add(obj);
      for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
        collected.push(key);
        const normalizedKey = this.normalizeString(key);
        if (normalizedKey !== key) {
          collected.push(normalizedKey);
        }
        this.collectStringValues(val, collected, visited);
      }
    }

    return collected;
  }
}
