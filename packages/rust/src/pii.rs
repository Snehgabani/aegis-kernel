use regex::Regex;
use std::collections::HashMap;
use std::sync::Mutex;
use crate::types::{AegisSeverity, AegisViolation, RegexConditionParams, ToolCall};

pub struct PiiChecker {
    default_patterns: HashMap<String, Regex>,
    custom_patterns: Mutex<HashMap<String, Regex>>,
}

impl PiiChecker {
    pub fn new() -> Self {
        let mut default_patterns = HashMap::new();
        default_patterns.insert("CREDIT_CARD".to_string(), Regex::new(r"\b(?:4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|5[1-5][0-9]{2}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}|6(?:011|5[0-9]{2})[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})\b").unwrap());
        default_patterns.insert("US_SSN".to_string(), Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
        default_patterns.insert("EMAIL".to_string(), Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap());
        default_patterns.insert("IP_ADDRESS".to_string(), Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap());
        default_patterns.insert("OPENAI_API_KEY".to_string(), Regex::new(r"\b(?:sk-ant-api[0-9a-zA-Z_-]{15,}|sk-(?:proj-|live-)?[a-zA-Z0-9_-]{20,})\b").unwrap());
        default_patterns.insert("GITHUB_TOKEN".to_string(), Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{20,}\b").unwrap());
        default_patterns.insert("AWS_ACCESS_KEY".to_string(), Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap());
        default_patterns.insert("STRIPE_KEY".to_string(), Regex::new(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b").unwrap());
        default_patterns.insert("GENERIC_BEARER".to_string(), Regex::new(r"\bBearer\s+[A-Za-z0-9\-_.]{15,}\b").unwrap());
        default_patterns.insert("JWT_TOKEN".to_string(), Regex::new(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b").unwrap());
        default_patterns.insert("SLACK_TOKEN".to_string(), Regex::new(r"\bxox[baprs]-[0-9a-zA-Z-]{10,64}\b").unwrap());
        default_patterns.insert("SENDGRID_KEY".to_string(), Regex::new(r"\bSG\.[0-9a-zA-Z_-]{16,32}\.[0-9a-zA-Z_-]{32,64}\b").unwrap());
        default_patterns.insert("AZURE_KEY".to_string(), Regex::new(r"(?i)\b(?:secret|api_key)_[a-zA-Z0-9_]{10,}\b").unwrap());
        default_patterns.insert("PRIVATE_KEY".to_string(), Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap());
        default_patterns.insert("US_TAX_ID".to_string(), Regex::new(r"\b\d{2}-\d{7}\b").unwrap());
        default_patterns.insert("DRIVER_LICENSE".to_string(), Regex::new(r"(?i)\bDriver License:\s*[A-Z0-9]{6,10}\b").unwrap());
        default_patterns.insert("MEDICAL_RECORD_NUMBER".to_string(), Regex::new(r"(?i)\bMRN:\s*\d{6,10}\b").unwrap());
        default_patterns.insert("US_NPI".to_string(), Regex::new(r"\b[12]\d{9}\b").unwrap());
        default_patterns.insert("US_DEA".to_string(), Regex::new(r"\b[A-Z]{2}\d{7}\b").unwrap());
        default_patterns.insert("CREDIT_CARD_CVV".to_string(), Regex::new(r"(?i)\b(?:cvv|cvc|cvn|cid)\s*[:=]\s*\d{3,4}\b").unwrap());
        default_patterns.insert("SENSITIVE_FILE_PATH".to_string(), Regex::new(r"(?:/etc/(?:shadow|passwd|sudoers)|\.ssh/(?:id_rsa|authorized_keys)|\.env(?:\.[a-zA-Z0-9_-]+)?|/proc/self/environ)").unwrap());
        default_patterns.insert("DESTRUCTIVE_COMMAND".to_string(), Regex::new(r"(?i)\b(?:rm\s+-(?:r|f|rf|fr)\s+[/\\*]|mkfs|dd\s+if=|:\(\)\s*\{\s*:\|:&\s*\};:)").unwrap());
        default_patterns.insert("SYSTEM_PROMPT_LEAKAGE".to_string(), Regex::new(r"(?i)(?:<\|im_start\|>system|<\|begin_of_text\|>|You are an AI assistant who must always|Internal system instructions:|=== SYSTEM INSTRUCTIONS ===)").unwrap());
        default_patterns.insert("MARKDOWN_EXFILTRATION".to_string(), Regex::new(r"(?i)\[.*?\]\((?:https?://[^\s)]+\?(?:leak|exfil|data|key|token|cookie)=[^\s)]+)\)").unwrap());
        default_patterns.insert("CANARY_TOKEN".to_string(), Regex::new(r"\b(?:CANARY-[A-Za-z0-9_-]{12,}|FLAG\{[A-Za-z0-9_-]{8,}\})\b").unwrap());
        default_patterns.insert("INTERNATIONAL_PHONE".to_string(), Regex::new(r"\+(?:[0-9][ -]?){6,14}[0-9]").unwrap());
        default_patterns.insert("IBAN".to_string(), Regex::new(r"\b[A-Z]{2}[0-9]{2}[ -]?(?:[A-Z0-9]{4}[ -]?){1,7}[A-Z0-9]{1,4}\b").unwrap());

        Self {
            default_patterns,
            custom_patterns: Mutex::new(HashMap::new()),
        }
    }

    pub fn normalize_string(&self, text: &str) -> String {
        text.chars().filter(|&c| {
            let u = c as u32;
            !((0x200B..=0x200D).contains(&u) || u == 0x2060 || u == 0xFEFF || u == 0x00AD || (0x202A..=0x202E).contains(&u))
        }).collect()
    }

    fn get_regex(&self, pattern_name: &str) -> Option<Regex> {
        if let Some(re) = self.default_patterns.get(pattern_name) {
            return Some(re.clone());
        }

        let mut custom = self.custom_patterns.lock().unwrap();
        if let Some(re) = custom.get(pattern_name) {
            return Some(re.clone());
        }

        if let Ok(re) = Regex::new(&format!("(?i){}", pattern_name)) {
            custom.insert(pattern_name.to_string(), re.clone());
            return Some(re);
        }
        if let Ok(re) = Regex::new(pattern_name) {
            custom.insert(pattern_name.to_string(), re.clone());
            return Some(re);
        }

        None
    }

    fn collect_strings(&self, val: &serde_json::Value, out: &mut Vec<String>) {
        match val {
            serde_json::Value::String(s) => {
                out.push(s.clone());
                let norm = self.normalize_string(s);
                if norm != *s {
                    out.push(norm);
                }
            }
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    out.push(k.clone());
                    self.collect_strings(v, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.collect_strings(item, out);
                }
            }
            serde_json::Value::Number(n) => out.push(n.to_string()),
            serde_json::Value::Bool(b) => out.push(b.to_string()),
            serde_json::Value::Null => {}
        }
    }

    pub fn evaluate(
        &self,
        rule_id: &str,
        pack_id: &str,
        params: &RegexConditionParams,
        call: &ToolCall,
        severity: AegisSeverity,
    ) -> Vec<AegisViolation> {
        let mut violations = Vec::new();
        let mut text_values = Vec::new();

        for (k, v) in &call.arguments {
            text_values.push(k.clone());
            self.collect_strings(v, &mut text_values);
        }

        let effective_severity = if params.match_action.as_deref() == Some("warn") {
            AegisSeverity::Warning
        } else {
            severity
        };

        for pattern_name in &params.patterns {
            if let Some(regex) = self.get_regex(pattern_name) {
                for text in &text_values {
                    if regex.is_match(text) {
                        violations.push(AegisViolation {
                            rule_id: rule_id.to_string(),
                            pack_id: pack_id.to_string(),
                            severity: effective_severity.clone(),
                            message: format!("Sensitive credential or PII pattern '{}' detected in tool arguments.", pattern_name),
                            suggested_fix: Some(format!("Redact or parameterize sensitive tokens before invoking tool '{}'.", call.name)),
                            context: None,
                        });
                        break; // One violation per pattern
                    }
                }
            }
        }

        violations
    }
}
