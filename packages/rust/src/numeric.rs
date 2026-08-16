use regex::Regex;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::types::{AegisSeverity, AegisViolation, NumericConditionParams, ToolCall};

pub struct NumericChecker {
    financial_aliases: Vec<String>,
    rate_limit_windows: Mutex<HashMap<String, Vec<u128>>>,
}

enum ExtractionStatus {
    Valid(f64),
    Invalid(serde_json::Value),
    Absent,
}

impl NumericChecker {
    pub fn new() -> Self {
        let financial_aliases = [
            "amount", "total", "value", "sum", "price", "cost", "payout", "payment",
            "transfer", "balance", "limit", "fee", "debit", "credit", "charge", "subtotal"
        ].iter().map(|s| s.to_string()).collect();

        Self {
            financial_aliases,
            rate_limit_windows: Mutex::new(HashMap::new()),
        }
    }

    pub fn parse_numeric_value(&self, val: &serde_json::Value) -> Option<f64> {
        match val {
            serde_json::Value::Number(num) => num.as_f64(),
            serde_json::Value::String(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("nan") || trimmed.eq_ignore_ascii_case("infinity") {
                    return None;
                }

                let mut cleaned = trimmed.to_string();
                let sym_re = Regex::new(r"[$€£¥₹]").unwrap();
                cleaned = sym_re.replace_all(&cleaned, "").to_string();
                let code_re = Regex::new(r"(?i)\b(USD|EUR|GBP|CAD|AUD|INR|JPY|CHF|CNY)\b").unwrap();
                cleaned = code_re.replace_all(&cleaned, "").to_string();
                cleaned = cleaned.replace(',', "");
                let cleaned_trimmed = cleaned.trim();

                cleaned_trimmed.parse::<f64>().ok().filter(|f| f.is_finite())
            }
            _ => None,
        }
    }

    fn extract_nested_number(&self, params: &HashMap<String, serde_json::Value>, path_str: &str) -> ExtractionStatus {
        let clean_path = path_str.trim_start_matches("params.");
        let parts: Vec<&str> = clean_path.split('.').collect();

        if let Some(target_val) = self.get_path_value(params, &parts) {
            if let Some(num) = self.parse_numeric_value(target_val) {
                return ExtractionStatus::Valid(num);
            }
            return ExtractionStatus::Invalid(target_val.clone());
        }

        // Recursive search for target field
        if let Some(last_part) = parts.last() {
            if let Some(found_val) = self.find_nested_value(params, last_part) {
                if let Some(num) = self.parse_numeric_value(found_val) {
                    return ExtractionStatus::Valid(num);
                }
                return ExtractionStatus::Invalid(found_val.clone());
            }

            // Semantic alias search for financial fields
            let lower_target = last_part.to_lowercase();
            if self.financial_aliases.contains(&lower_target) {
                for alias in &self.financial_aliases {
                    if *alias == lower_target {
                        continue;
                    }
                    if let Some(alias_val) = self.find_nested_value(params, alias) {
                        if let Some(num) = self.parse_numeric_value(alias_val) {
                            return ExtractionStatus::Valid(num);
                        }
                        return ExtractionStatus::Invalid(alias_val.clone());
                    }
                }
            }
        }

        ExtractionStatus::Absent
    }

    fn get_path_value<'a>(&self, params: &'a HashMap<String, serde_json::Value>, parts: &[&str]) -> Option<&'a serde_json::Value> {
        if parts.is_empty() {
            return None;
        }

        let mut current = params.get(parts[0])?;
        for &part in &parts[1..] {
            if let serde_json::Value::Object(map) = current {
                current = map.get(part)?;
            } else {
                return None;
            }
        }
        Some(current)
    }

    fn find_nested_value<'a>(&self, params: &'a HashMap<String, serde_json::Value>, target: &str) -> Option<&'a serde_json::Value> {
        let lower_target = target.to_lowercase();
        for (k, v) in params {
            if k.to_lowercase() == lower_target {
                return Some(v);
            }
        }

        for v in params.values() {
            if let serde_json::Value::Object(map) = v {
                if let Some(found) = self.find_nested_value_map(map, target) {
                    return Some(found);
                }
            }
        }

        None
    }

    fn find_nested_value_map<'a>(&self, map: &'a serde_json::Map<String, serde_json::Value>, target: &str) -> Option<&'a serde_json::Value> {
        let lower_target = target.to_lowercase();
        for (k, v) in map {
            if k.to_lowercase() == lower_target {
                return Some(v);
            }
        }

        for v in map.values() {
            if let serde_json::Value::Object(sub_map) = v {
                if let Some(found) = self.find_nested_value_map(sub_map, target) {
                    return Some(found);
                }
            }
        }

        None
    }

    pub fn evaluate(
        &self,
        rule_id: &str,
        pack_id: &str,
        params: &NumericConditionParams,
        call: &ToolCall,
        severity: AegisSeverity,
    ) -> Vec<AegisViolation> {
        let mut violations = Vec::new();

        let extraction = self.extract_nested_number(&call.arguments, &params.field);

        match extraction {
            ExtractionStatus::Absent => return violations,
            ExtractionStatus::Invalid(raw) => {
                violations.push(AegisViolation {
                    rule_id: rule_id.to_string(),
                    pack_id: pack_id.to_string(),
                    severity,
                    message: format!("Numeric parameter '{}' contains invalid non-numeric value: {}.", params.field, raw),
                    suggested_fix: Some(format!("Ensure '{}' is a valid finite numeric value or formatted currency string.", params.field)),
                    context: None,
                });
                return violations;
            }
            ExtractionStatus::Valid(val) => {
                // Default min: 0 for financial aliases
                let mut effective_min = params.min;
                if effective_min.is_none() {
                    let lower_field = params.field.to_lowercase();
                    if self.financial_aliases.iter().any(|a| lower_field.contains(a)) {
                        effective_min = Some(0.0);
                    }
                }

                if let Some(min_val) = effective_min {
                    if val < min_val {
                        violations.push(AegisViolation {
                            rule_id: rule_id.to_string(),
                            pack_id: pack_id.to_string(),
                            severity: severity.clone(),
                            message: format!("Numeric parameter '{}' ({}) is below minimum allowed value of {}.", params.field, val, min_val),
                            suggested_fix: Some(format!("Increase value of '{}' to at least {}.", params.field, min_val)),
                            context: None,
                        });
                    }
                }

                if let Some(max_val) = params.max {
                    if val > max_val {
                        violations.push(AegisViolation {
                            rule_id: rule_id.to_string(),
                            pack_id: pack_id.to_string(),
                            severity: severity.clone(),
                            message: format!("Numeric parameter '{}' ({}) exceeds maximum allowed limit of {}.", params.field, val, max_val),
                            suggested_fix: Some(format!("Reduce value of '{}' to {} or less.", params.field, max_val)),
                            context: None,
                        });
                    }
                }

                // Sliding window rate limit
                if let Some(rate_limit) = &params.rate_limit {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
                    let window_ms = 60 * 1000;
                    let key = format!("{}:{}:{}", pack_id, rule_id, call.name);

                    let mut windows = self.rate_limit_windows.lock().unwrap();
                    let timestamps = windows.entry(key).or_insert_with(Vec::new);
                    timestamps.retain(|&t| now.saturating_sub(t) < window_ms);
                    timestamps.push(now);
                    let count = timestamps.len();

                    if count > rate_limit.max_per_minute {
                        violations.push(AegisViolation {
                            rule_id: rule_id.to_string(),
                            pack_id: pack_id.to_string(),
                            severity,
                            message: format!("Rate limit ceiling reached: Tool '{}' invoked {} times in past minute (max: {}).", call.name, count, rate_limit.max_per_minute),
                            suggested_fix: Some("Throttle tool invocation frequency or batch operations.".to_string()),
                            context: None,
                        });
                    }
                }
            }
        }

        violations
    }
}
