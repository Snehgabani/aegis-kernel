import type { AegisSeverity, AegisViolation, EvaluationScratch, RegexConditionParams, ToolCall } from '../types.js';
import { HOMOGLYPH_MAP } from '../normalizers/homoglyphs.generated.js';

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

const INVISIBLE_EVASION_RE =
  /[\u00AD\u061C\u180E\u2000-\u200F\u202A-\u202E\u202F\u205F\u2060-\u2064\u2066-\u206F\u3000\uFEFF]/g;
const PCT_RUN_RE = /(?:%[0-9A-Fa-f]{2}){3,}/;
const HEX_RUN_RE = /(?:\\x[0-9A-Fa-f]{2}){3,}/;
const B64_RUN_RE = /[A-Za-z0-9+/=_-]{16,}/g;
const NON_ASCII_RE = /[^\x00-\x7F]/;

/** Bounded string-keyed memo helpers — strings are immutable, so cross-call caching is safe. */
function memoGet<T>(cache: Map<string, T>, key: string): T | undefined {
  return cache.get(key);
}
function memoSet<T>(cache: Map<string, T>, key: string, value: T, cap: number): void {
  if (cache.size >= cap) {
    const first = cache.keys().next().value;
    if (first !== undefined) cache.delete(first);
  }
  cache.set(key, value);
}

export class PiiChecker {
  private compiledPatterns: Map<string, RegExp>;
  /** normalizeString results, keyed by immutable input string (bounded, cross-call safe). */
  private normalizeMemo: Map<string, string>;
  /** foldHomoglyphs results (bounded, cross-call safe). */
  private foldMemo: Map<string, string>;
  /** decodeEvasions results (bounded, cross-call safe — pure function of the string). */
  private decodeMemo: Map<string, string[]>;

  private static readonly NORMALIZE_MEMO_CAP = 4096;
  private static readonly FOLD_MEMO_CAP = 4096;
  private static readonly DECODE_MEMO_CAP = 2048;

  constructor() {
    this.compiledPatterns = new Map();
    this.normalizeMemo = new Map();
    this.foldMemo = new Map();
    this.decodeMemo = new Map();
  }

  public evaluate(
    ruleId: string,
    packId: string,
    params: RegexConditionParams,
    toolCall: ToolCall,
    severity: AegisSeverity = 'critical',
    scratch?: EvaluationScratch
  ): AegisViolation[] {
    const violations: AegisViolation[] = [];
    const textValues = params.field
      ? (typeof (toolCall.params as any)?.[params.field] === 'string' ? [(toolCall.params as any)[params.field]] : [])
      : this.collectStringValuesCached(toolCall.params, scratch);

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

  /**
   * Per-evaluate memoization of the parameter tree walk: 8 regex rules visit
   * the same params object within one evaluate(); the collection (including
   * normalization, confusable folding and evasion decode variants) is computed
   * once per call instead of 8×.
   */
  private collectStringValuesCached(
    params: Record<string, unknown>,
    scratch?: EvaluationScratch
  ): string[] {
    if (scratch && params && typeof params === 'object') {
      const cached = scratch.piiCollected.get(params);
      if (cached) return cached;
      const collected = this.collectStringValues(params);
      scratch.piiCollected.set(params, collected);
      return collected;
    }
    return this.collectStringValues(params);
  }

  private normalizeString(text: string): string {
    // Fast lane: pure ASCII input contains no zero-width/bidi/fullwidth
    // evasion characters and needs no NFKD decomposition or stripping.
    if (!NON_ASCII_RE.test(text)) {
      return text;
    }
    const cached = memoGet(this.normalizeMemo, text);
    if (cached !== undefined) return cached;
    // Strip zero-width, bidi-override/-isolate, space-separator, and invisible
    // control characters used for regex evasion. Red-team hardened 2026-08-20:
    // the original narrow set was bypassable with EN-SPACES between digits and
    // bidi isolates (see red-team harness, TAP PII exfiltration tree).
    const stripped = text.replace(INVISIBLE_EVASION_RE, '');
    // Normalize unicode forms (NFKD)
    const result = stripped.normalize('NFKD');
    memoSet(this.normalizeMemo, text, result, PiiChecker.NORMALIZE_MEMO_CAP);
    return result;
  }

  /**
   * Confusable folding (UTS #39 map) — applied before decode attempts because
   * attackers homoglyph-corrupt the base64 ALPHABET itself (Cyrillic look-alikes
   * inside the run): the attacker can reverse their own mapping, so the scanner
   * must fold before decoding to see the same payload.
   */
  private foldHomoglyphs(text: string): string {
    // Fast lane: the homoglyph map only contains non-ASCII code points.
    if (!NON_ASCII_RE.test(text)) {
      return text;
    }
    const cached = memoGet(this.foldMemo, text);
    if (cached !== undefined) return cached;
    const result = Array.from(text)
      .map((ch) => HOMOGLYPH_MAP[ch] ?? ch)
      .join('');
    memoSet(this.foldMemo, text, result, PiiChecker.FOLD_MEMO_CAP);
    return result;
  }

  private static readonly MAX_DECODE_DEPTH = 3;
  private static readonly MAX_DECODE_VARIANTS = 16;

  /**
   * Layered evasion decoding (2026-08-20, red-team finding). Bounded recursive
   * cascade: at each layer, fold confusables + strip invisibles/separators, then
   * attempt percent / hex / base64 decodes and recurse into decoded results.
   * Catches base64(base64(spaced(homoglyph(PII))))-style layering. Bounds:
   * depth ≤ 3, ≤16 variants, ≤4KB per run — hot-path safe.
   */
  private decodeEvasions(text: string): string[] {
    // Fast lane: no encoding markers and no run long enough to be base64.
    if (text.length < 16 && text.indexOf('%') === -1 && text.indexOf('\\') === -1) {
      return [];
    }
    const cached = memoGet(this.decodeMemo, text);
    if (cached !== undefined) return cached;

    const out: string[] = [];
    const seen = new Set<string>();

    const tryPush = (candidate: string): void => {
      if (candidate.length < 4 || out.length >= PiiChecker.MAX_DECODE_VARIANTS) return;
      // Keep decodes that are mostly printable AFTER stripping invisible
      // evasion chars (a decoded payload with separators is still a payload)
      const printable = candidate.replace(/[^\x20-\x7E\n\r\t]/g, '');
      if (printable.length / candidate.length > 0.7 && !seen.has(candidate)) {
        seen.add(candidate);
        out.push(candidate);
      }
    };

    const cascade = (input: string, depth: number): void => {
      if (depth > PiiChecker.MAX_DECODE_DEPTH) return;
      const clean = this.normalizeString(this.foldHomoglyphs(input));
      tryPush(clean);

      // Percent-encoding (%41%42…): 3+ consecutive sequences
      const pctMatch = clean.match(PCT_RUN_RE);
      if (pctMatch) {
        try {
          cascade(decodeURIComponent(pctMatch[0]), depth + 1);
        } catch {
          /* malformed — ignore */
        }
      }

      // Hex escapes (\x41\x42…)
      const hexMatch = clean.match(HEX_RUN_RE);
      if (hexMatch) {
        cascade(
          hexMatch[0].replace(/\\x([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))),
          depth + 1
        );
      }

      // Base64 runs (≥16 chars, standard or URL-safe)
      const b64Runs = clean.match(B64_RUN_RE) ?? [];
      for (const run of b64Runs.slice(0, 4)) {
        if (run.length > 4096) continue;
        const normalizedB64 = run.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
        if (normalizedB64.length < 16) continue;
        try {
          const decoded = Buffer.from(normalizedB64, 'base64').toString('utf8');
          if (decoded.replace(/[^\x00-\x7F]/g, '').length >= 4) {
            cascade(decoded, depth + 1);
          }
        } catch {
          /* not valid base64 — ignore */
        }
      }
    };

    cascade(text, 0);
    memoSet(this.decodeMemo, text, out, PiiChecker.DECODE_MEMO_CAP);
    return out;
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
      // Direct confusable folding (homoglyph'd PII without encoding layers)
      const folded = this.foldHomoglyphs(normalized);
      if (folded !== normalized && !collected.includes(folded)) {
        collected.push(folded);
      }
      // Red-team hardening: scan decoded-evasion variants of this string too
      for (const variant of this.decodeEvasions(normalized)) {
        if (!collected.includes(variant)) {
          collected.push(variant);
        }
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
