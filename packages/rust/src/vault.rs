use crate::crypto::HmacSha256;
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TokenizeResult {
    pub sanitized: String,
    pub tokens_created: usize,
    pub token_types: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
pub struct DetokenizeResult {
    pub restored: String,
    pub tokens_restored: usize,
}

pub struct PiiTokenVault {
    vault: HashMap<String, String>, // Token -> original value
    value_to_token_map: HashMap<String, String>,
    token_prefix: String,
    hash_length: usize,
    session_salt: Vec<u8>,
    patterns: HashMap<String, Regex>,
}

impl PiiTokenVault {
    pub fn new(token_prefix: Option<&str>, hash_length: Option<usize>, salt: Option<Vec<u8>>) -> Self {
        let mut patterns = HashMap::new();
        patterns.insert("CREDIT_CARD".to_string(), Regex::new(r"\b(?:4[0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|5[1-5][0-9]{2}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|3[47][0-9]{2}[ -]?[0-9]{6}[ -]?[0-9]{5}|6(?:011|5[0-9]{2})[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4})\b").unwrap());
        patterns.insert("US_SSN".to_string(), Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
        patterns.insert("EMAIL".to_string(), Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap());
        patterns.insert("OPENAI_API_KEY".to_string(), Regex::new(r"\b(?:sk-ant-api[0-9a-zA-Z_-]{15,}|sk-(?:proj-|live-)?[a-zA-Z0-9_-]{20,})\b").unwrap());
        patterns.insert("GITHUB_TOKEN".to_string(), Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{20,}\b").unwrap());
        patterns.insert("AWS_ACCESS_KEY".to_string(), Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap());
        patterns.insert("STRIPE_KEY".to_string(), Regex::new(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b").unwrap());
        patterns.insert("SLACK_TOKEN".to_string(), Regex::new(r"\bxox[baprs]-[0-9a-zA-Z-]{10,64}\b").unwrap());
        patterns.insert("JWT_TOKEN".to_string(), Regex::new(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b").unwrap());

        let session_salt = salt.unwrap_or_else(|| {
            let mut s = Vec::with_capacity(16);
            let time_bytes = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos().to_be_bytes();
            s.extend_from_slice(&time_bytes);
            s
        });

        Self {
            vault: HashMap::new(),
            value_to_token_map: HashMap::new(),
            token_prefix: token_prefix.unwrap_or("").to_string(),
            hash_length: hash_length.unwrap_or(16),
            session_salt,
            patterns,
        }
    }

    pub fn tokenize(&mut self, text: &str) -> TokenizeResult {
        if text.is_empty() {
            return TokenizeResult {
                sanitized: text.to_string(),
                tokens_created: 0,
                token_types: HashMap::new(),
            };
        }

        let mut sanitized = text.to_string();
        let mut tokens_created = 0;
        let mut token_types = HashMap::new();

        for (pattern_name, regex) in &self.patterns {
            let matches: Vec<String> = regex.find_iter(&sanitized).map(|m| m.as_str().to_string()).collect();

            for m in matches {
                let token = if let Some(existing) = self.value_to_token_map.get(&m) {
                    existing.clone()
                } else {
                    let mut mac = HmacSha256::new_from_slice(&self.session_salt);
                    mac.update(m.as_bytes());
                    let hash_bytes = mac.finalize();
                    let full_hex = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                    let hash_slice = if full_hex.len() > self.hash_length {
                        &full_hex[..self.hash_length]
                    } else {
                        &full_hex
                    };

                    let prefix = if !self.token_prefix.is_empty() {
                        &self.token_prefix
                    } else {
                        pattern_name.as_str()
                    };

                    let tok = format!("<{}_{}>", prefix, hash_slice);
                    self.vault.insert(tok.clone(), m.clone());
                    self.value_to_token_map.insert(m.clone(), tok.clone());
                    tokens_created += 1;
                    *token_types.entry(pattern_name.clone()).or_insert(0) += 1;
                    tok
                };

                sanitized = sanitized.replace(&m, &token);
            }
        }

        TokenizeResult {
            sanitized,
            tokens_created,
            token_types,
        }
    }

    pub fn detokenize(&self, text: &str) -> DetokenizeResult {
        if text.is_empty() {
            return DetokenizeResult {
                restored: text.to_string(),
                tokens_restored: 0,
            };
        }

        let token_re = Regex::new(r"<[A-Za-z0-9_]+>").unwrap();
        let mut restored = text.to_string();
        let mut tokens_restored = 0;

        for mat in token_re.find_iter(text) {
            let tok_str = mat.as_str();
            if let Some(original) = self.vault.get(tok_str) {
                restored = restored.replace(tok_str, original);
                tokens_restored += 1;
            }
        }

        DetokenizeResult {
            restored,
            tokens_restored,
        }
    }

    pub fn clear(&mut self) {
        self.vault.clear();
        self.value_to_token_map.clear();
    }

    pub fn vault_size(&self) -> usize {
        self.vault.len()
    }
}
