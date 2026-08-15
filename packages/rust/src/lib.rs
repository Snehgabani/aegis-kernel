use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ToolCall {
    pub name: String,
    pub arguments: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Verdict {
    pub allowed: bool,
    pub violations: Vec<String>,
    pub latency_us: u128,
    pub proof_hash: String,
}

pub struct Config {
    pub enable_sql_validation: bool,
    pub enable_pii_scanning: bool,
    pub numeric_limits: HashMap<String, (f64, f64)>,
}

pub struct AegisEngine {
    config: Config,
    pii_regex: Regex,
}

impl AegisEngine {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            pii_regex: Regex::new(r"(?i)(ssn|social security|credit card|cc)[\s\-:]*\d{4}").unwrap(),
        }
    }

    pub fn evaluate(&self, call: &ToolCall) -> Verdict {
        let start = Instant::now();
        let mut allowed = true;
        let mut violations = Vec::new();

        if self.config.enable_sql_validation {
            if let Some(query) = call.arguments.get("query").and_then(|v| v.as_str()) {
                let upper_query = query.to_uppercase();
                if upper_query.contains("DROP ") || upper_query.contains("TRUNCATE ") || upper_query.contains("ALTER ") {
                    violations.push("destructive SQL operation not allowed".to_string());
                    allowed = false;
                }
                if upper_query.contains("DELETE FROM ") && !upper_query.contains(" WHERE ") {
                    violations.push("DELETE without WHERE clause not allowed".to_string());
                    allowed = false;
                }
            }
        }

        if self.config.enable_pii_scanning {
            for val in call.arguments.values() {
                if let Some(s) = val.as_str() {
                    if self.pii_regex.is_match(s) {
                        violations.push("PII detected".to_string());
                        allowed = false;
                    }
                }
            }
        }

        for (arg_name, (min, max)) in &self.config.numeric_limits {
            if let Some(val) = call.arguments.get(arg_name) {
                if let Some(num) = val.as_f64() {
                    if num < *min || num > *max {
                        violations.push(format!("argument {} out of bounds", arg_name));
                        allowed = false;
                    }
                }
            }
        }

        let latency_us = start.elapsed().as_micros();
        
        let mut hasher = Sha256::new();
        hasher.update(call.name.as_bytes());
        hasher.update(allowed.to_string().as_bytes());
        let proof_hash = format!("{:x}", hasher.finalize());

        Verdict {
            allowed,
            violations,
            latency_us,
            proof_hash,
        }
    }
}
