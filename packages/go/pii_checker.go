package aegis

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// DefaultPiiPatterns contains pre-compiled regular expressions for secrets, PII, and sensitive invariants
var DefaultPiiPatterns = map[string]*regexp.Regexp{
	"CREDIT_CARD": regexp.MustCompile(`\b(?:4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|5[1-5][0-9]{2}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}|6(?:011|5[0-9]{2})[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})\b`),
	"US_SSN":      regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	"EMAIL":       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
	"IP_ADDRESS":  regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	"OPENAI_API_KEY": regexp.MustCompile(`\b(?:sk-ant-api[0-9a-zA-Z_-]{15,}|sk-(?:proj-|live-)?[a-zA-Z0-9_-]{20,})\b`),
	"GITHUB_TOKEN": regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{20,}\b`),
	"AWS_ACCESS_KEY": regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	"STRIPE_KEY": regexp.MustCompile(`\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b`),
	"GENERIC_BEARER": regexp.MustCompile(`\bBearer\s+[A-Za-z0-9\-_.]{15,}\b`),
	"JWT_TOKEN": regexp.MustCompile(`\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b`),
	"SLACK_TOKEN": regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z-]{10,64}\b`),
	"SENDGRID_KEY": regexp.MustCompile(`\bSG\.[0-9a-zA-Z_-]{16,32}\.[0-9a-zA-Z_-]{32,64}\b`),
	"AZURE_KEY": regexp.MustCompile(`(?i)\b(?:secret|api_key)_[a-zA-Z0-9_]{10,}\b`),
	"PRIVATE_KEY": regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
	"US_TAX_ID": regexp.MustCompile(`\b\d{2}-\d{7}\b`),
	"DRIVER_LICENSE": regexp.MustCompile(`(?i)\bDriver License:\s*[A-Z0-9]{6,10}\b`),
	"MEDICAL_RECORD_NUMBER": regexp.MustCompile(`(?i)\bMRN:\s*\d{6,10}\b`),
	"US_NPI": regexp.MustCompile(`\b[12]\d{9}\b`),
	"US_DEA": regexp.MustCompile(`\b[A-Z]{2}\d{7}\b`),
	"CREDIT_CARD_CVV": regexp.MustCompile(`(?i)\b(?:cvv|cvc|cvn|cid)\s*[:=]\s*\d{3,4}\b`),
	"SENSITIVE_FILE_PATH": regexp.MustCompile(`(?:\/etc\/(?:shadow|passwd|sudoers)|\.ssh\/(?:id_rsa|authorized_keys)|\.env(?:\.[a-zA-Z0-9_-]+)?|\/proc\/self\/environ)`),
	"DESTRUCTIVE_COMMAND": regexp.MustCompile(`(?i)\b(?:rm\s+-(?:r|f|rf|fr)\s+[\/\*]|mkfs|dd\s+if=|\:(){ \:\|\: & }\;:\b)`),
	"SYSTEM_PROMPT_LEAKAGE": regexp.MustCompile(`(?i)(?:<\|im_start\|>system|<\|begin_of_text\|>|You are an AI assistant who must always|Internal system instructions:|=== SYSTEM INSTRUCTIONS ===)`),
	"MARKDOWN_EXFILTRATION": regexp.MustCompile(`(?i)\[.*?\]\((?:https?:\/\/[^\s)]+\?(?:leak|exfil|data|key|token|cookie)=[^\s)]+)\)`),
	"CANARY_TOKEN": regexp.MustCompile(`\b(?:CANARY-[A-Za-z0-9_-]{12,}|FLAG\{[A-Za-z0-9_-]{8,}\})\b`),
	"INTERNATIONAL_PHONE": regexp.MustCompile(`\+(?:[0-9][ -]?){6,14}[0-9]`),
	"IBAN": regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[ -]?(?:[A-Z0-9]{4}[ -]?){1,7}[A-Z0-9]{1,4}\b`),
}

// PiiChecker performs regex pattern detection for secrets, credentials, and sensitive data
type PiiChecker struct {
	mu            sync.RWMutex
	customPattern map[string]*regexp.Regexp
}

// NewPiiChecker creates a new PiiChecker
func NewPiiChecker() *PiiChecker {
	return &PiiChecker{
		customPattern: make(map[string]*regexp.Regexp),
	}
}

// NormalizeString strips zero-width and control characters to prevent evasion
func (pc *PiiChecker) NormalizeString(text string) string {
	var sb strings.Builder
	for _, r := range text {
		if (r >= 0x200B && r <= 0x200D) || r == 0x2060 || r == 0xFEFF || r == 0x00AD || (r >= 0x202A && r <= 0x202E) {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func (pc *PiiChecker) getRegex(patternStr string) (*regexp.Regexp, error) {
	if re, ok := DefaultPiiPatterns[patternStr]; ok {
		return re, nil
	}

	pc.mu.RLock()
	if re, ok := pc.customPattern[patternStr]; ok {
		pc.mu.RUnlock()
		return re, nil
	}
	pc.mu.RUnlock()

	pc.mu.Lock()
	defer pc.mu.Unlock()

	if re, ok := pc.customPattern[patternStr]; ok {
		return re, nil
	}

	re, err := regexp.Compile("(?i)" + patternStr)
	if err != nil {
		re, err = regexp.Compile(patternStr)
		if err != nil {
			return nil, err
		}
	}
	pc.customPattern[patternStr] = re
	return re, nil
}

func (pc *PiiChecker) collectStringValues(obj interface{}, visited map[string]bool) []string {
	var results []string
	if obj == nil {
		return results
	}

	switch v := obj.(type) {
	case string:
		results = append(results, v)
		norm := pc.NormalizeString(v)
		if norm != v {
			results = append(results, norm)
		}
	case map[string]interface{}:
		for k, val := range v {
			results = append(results, k)
			results = append(results, pc.collectStringValues(val, visited)...)
		}
	case []interface{}:
		for _, item := range v {
			results = append(results, pc.collectStringValues(item, visited)...)
		}
	default:
		results = append(results, fmt.Sprintf("%v", v))
	}

	return results
}

// Evaluate scans tool call arguments for sensitive credentials and PII
func (pc *PiiChecker) Evaluate(
	ruleID string,
	packID string,
	params RegexConditionParams,
	call ToolCall,
	severity AegisSeverity,
) []AegisViolation {
	var violations []AegisViolation
	textValues := pc.collectStringValues(call.GetParams(), make(map[string]bool))

	if severity == "" {
		severity = SeverityCritical
	}
	if params.MatchAction == "warn" {
		severity = SeverityWarning
	}

	for _, patternName := range params.Patterns {
		re, err := pc.getRegex(patternName)
		if err != nil {
			continue
		}

		for _, text := range textValues {
			if re.MatchString(text) {
				match := re.FindString(text)
				sanitized := "***"
				if len(match) > 4 {
					sanitized = match[:4] + "***"
				}

				violations = append(violations, AegisViolation{
					RuleID:       ruleID,
					PackID:       packID,
					Severity:     severity,
					Message:      fmt.Sprintf("Sensitive credential or PII pattern '%s' detected in tool arguments.", patternName),
					SuggestedFix: fmt.Sprintf("Redact or parameterize sensitive tokens before invoking tool '%s'.", call.GetToolName()),
					Context: map[string]interface{}{
						"pattern": patternName,
						"sample":  sanitized,
					},
				})
				break // One violation per pattern
			}
		}
	}

	return violations
}
