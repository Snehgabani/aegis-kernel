use crate::crypto::Sha256;
use crate::numeric::NumericChecker;
use crate::pii::PiiChecker;
use crate::sql::SqlChecker;
use crate::state::StateChecker;
use crate::types::{
    AegisMode, AegisSeverity, AegisViolation, Config, NumericConditionParams, RegexConditionParams,
    Rule, RuleCondition, RulePack, SqlAstConditionParams, StateInvariantConditionParams, ToolCall,
    Verdict,
};
use std::collections::HashMap;
use std::time::Instant;

/// Rule parameters parsed ONCE at engine construction into typed structs.
///
/// The historical implementation re-parsed every rule's
/// `HashMap<String, serde_json::Value>` params on EVERY evaluate() call,
/// allocating Strings/Vecs per rule per call. Pre-compilation moves that
/// work to construction time; the hot path only borrows the typed params.
struct CompiledRule {
    id: String,
    pack_id: String,
    severity: AegisSeverity,
    kind: CompiledRuleKind,
}

enum CompiledRuleKind {
    Sql(SqlAstConditionParams),
    Numeric(NumericConditionParams),
    Regex(RegexConditionParams),
    State(StateInvariantConditionParams),
    Other,
}

fn compile_rules(packs: &[RulePack]) -> Vec<CompiledRule> {
    let mut out = Vec::new();
    for pack in packs {
        for rule in &pack.rules {
            let kind = match rule.condition.r#type.as_str() {
                "sql_ast" => {
                    let params = &rule.condition.params;
                    let get_strings = |key: &str| {
                        params
                            .get(key)
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|s| s.as_str().map(|x| x.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default()
                    };
                    CompiledRuleKind::Sql(SqlAstConditionParams {
                        statements: get_strings("statements"),
                        block_statements: get_strings("block_statements"),
                        require: params
                            .get("require")
                            .and_then(|v| v.as_str().map(|s| s.to_string())),
                        max_limit: params.get("max_limit").and_then(|v| v.as_i64()),
                        database_field: params
                            .get("database_field")
                            .and_then(|v| v.as_str().map(|s| s.to_string())),
                    })
                }
                "numeric" => {
                    let params = &rule.condition.params;
                    CompiledRuleKind::Numeric(NumericConditionParams {
                        field: params
                            .get("field")
                            .and_then(|v| v.as_str())
                            .unwrap_or("amount")
                            .to_string(),
                        min: params.get("min").and_then(|v| v.as_f64()),
                        max: params.get("max").and_then(|v| v.as_f64()),
                        rate_limit: None,
                    })
                }
                "regex" => {
                    let params = &rule.condition.params;
                    CompiledRuleKind::Regex(RegexConditionParams {
                        patterns: params
                            .get("patterns")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|s| s.as_str().map(|x| x.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        match_action: params
                            .get("match_action")
                            .and_then(|v| v.as_str().map(|s| s.to_string())),
                    })
                }
                "state_invariant" => {
                    let params = &rule.condition.params;
                    CompiledRuleKind::State(StateInvariantConditionParams {
                        target_field: params
                            .get("target_field")
                            .and_then(|v| v.as_str().map(|s| s.to_string())),
                        tenant_field: params
                            .get("tenant_field")
                            .and_then(|v| v.as_str().map(|s| s.to_string())),
                        require_state: params
                            .get("require_state")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        precondition: params
                            .get("precondition")
                            .and_then(|v| v.as_str().map(|s| s.to_string())),
                        assertion: params
                            .get("assertion")
                            .and_then(|v| v.as_str())
                            .unwrap_or("true")
                            .to_string(),
                    })
                }
                _ => CompiledRuleKind::Other,
            };
            out.push(CompiledRule {
                id: rule.id.clone(),
                pack_id: pack.id.clone(),
                severity: rule.severity.clone(),
                kind,
            });
        }
    }
    out
}

pub struct AegisEngine {
    config: Config,
    compiled_rules: Vec<CompiledRule>,
    sql_checker: SqlChecker,
    numeric_checker: NumericChecker,
    pii_checker: PiiChecker,
    state_checker: StateChecker,
    policy_commitment_hash: String,
}

impl AegisEngine {
    pub fn new(mut config: Config) -> Self {
        let mut rule_packs = std::mem::take(&mut config.rule_packs);

        if rule_packs.is_empty() {
            let mut rules = Vec::new();
            if config.enable_sql_validation {
                rules.extend(Self::default_sql_guard().rules);
            }
            if config.enable_pii_scanning {
                rules.extend(Self::default_data_guard().rules);
            }
            // Always include finance guard rules by default
            rules.extend(Self::default_finance_guard().rules);

            for (arg_name, (min_val, max_val)) in &config.numeric_limits {
                let mut params = HashMap::new();
                params.insert(
                    "field".to_string(),
                    serde_json::Value::String(arg_name.clone()),
                );
                params.insert("min".to_string(), serde_json::to_value(min_val).unwrap());
                params.insert("max".to_string(), serde_json::to_value(max_val).unwrap());

                rules.push(Rule {
                    id: format!("NUMERIC-{}", arg_name),
                    severity: AegisSeverity::Critical,
                    description: format!("Numeric limit on {}", arg_name),
                    suggested_fix: None,
                    condition: RuleCondition {
                        r#type: "numeric".to_string(),
                        params,
                    },
                });
            }
            rule_packs.push(RulePack {
                id: "default-guard-pack".to_string(),
                name: "Aegis Default Guard".to_string(),
                version: "1.0.0".to_string(),
                description: None,
                rules,
            });
        }

        let policy_commitment_hash = Self::compute_policy_commitment(&rule_packs);
        let compiled_rules = compile_rules(&rule_packs);

        Self {
            config,
            compiled_rules,
            sql_checker: SqlChecker::new(),
            numeric_checker: NumericChecker::new(),
            pii_checker: PiiChecker::new(),
            state_checker: StateChecker::new(),
            policy_commitment_hash,
        }
    }

    pub fn new_default() -> Self {
        Self::new(Config::default())
    }

    pub fn new_with_packs(packs: Vec<RulePack>) -> Self {
        let cfg = Config {
            rule_packs: packs,
            ..Default::default()
        };
        Self::new(cfg)
    }

    pub fn default_sql_guard() -> RulePack {
        let mut r1_params = HashMap::new();
        r1_params.insert("statements".to_string(), serde_json::json!(["DELETE"]));
        r1_params.insert("require".to_string(), serde_json::json!("WHERE_CLAUSE"));

        let mut r2_params = HashMap::new();
        r2_params.insert(
            "block_statements".to_string(),
            serde_json::json!(["DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE"]),
        );

        let mut r3_params = HashMap::new();
        r3_params.insert("statements".to_string(), serde_json::json!(["UPDATE"]));
        r3_params.insert("require".to_string(), serde_json::json!("WHERE_CLAUSE"));

        RulePack {
            id: "sql-guard".to_string(),
            name: "Aegis SQL Mutation & Destructive Operation Guard".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Enforces AST-level safety invariants on database queries".to_string()),
            rules: vec![
                Rule {
                    id: "SQL-001".to_string(),
                    severity: AegisSeverity::Critical,
                    description: "Prohibit DELETE statements without a WHERE clause".to_string(),
                    suggested_fix: Some("Add a targeted WHERE clause to delete specific rows.".to_string()),
                    condition: RuleCondition {
                        r#type: "sql_ast".to_string(),
                        params: r1_params,
                    },
                },
                Rule {
                    id: "SQL-002".to_string(),
                    severity: AegisSeverity::Critical,
                    description: "Prohibit destructive DROP, TRUNCATE, ALTER, GRANT, and REVOKE commands".to_string(),
                    suggested_fix: Some("Destructive DDL and privilege escalation statements are prohibited in production.".to_string()),
                    condition: RuleCondition {
                        r#type: "sql_ast".to_string(),
                        params: r2_params,
                    },
                },
                Rule {
                    id: "SQL-003".to_string(),
                    severity: AegisSeverity::Critical,
                    description: "Prohibit UPDATE statements without a WHERE clause".to_string(),
                    suggested_fix: Some("Add a specific WHERE clause to prevent updating all records.".to_string()),
                    condition: RuleCondition {
                        r#type: "sql_ast".to_string(),
                        params: r3_params,
                    },
                },
            ],
        }
    }

    pub fn default_finance_guard() -> RulePack {
        let mut r1_params = HashMap::new();
        r1_params.insert("field".to_string(), serde_json::json!("amount"));
        r1_params.insert("max".to_string(), serde_json::json!(10000.0));

        let mut r2_params = HashMap::new();
        r2_params.insert("target_field".to_string(), serde_json::json!("amount"));
        r2_params.insert(
            "precondition".to_string(),
            serde_json::json!("state.account_status == 'active'"),
        );
        r2_params.insert(
            "assertion".to_string(),
            serde_json::json!("state.spent_today + params.amount <= state.daily_budget"),
        );

        RulePack {
            id: "finance-guard".to_string(),
            name: "Aegis Financial Bounds Guard".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Enforces numeric limits and rate controls on payouts".to_string()),
            rules: vec![
                Rule {
                    id: "FIN-001".to_string(),
                    severity: AegisSeverity::Critical,
                    description: "Single transaction amount cannot exceed $10,000".to_string(),
                    suggested_fix: Some(
                        "Transaction amount exceeds maximum single-action ceiling of $10,000."
                            .to_string(),
                    ),
                    condition: RuleCondition {
                        r#type: "numeric".to_string(),
                        params: r1_params,
                    },
                },
                Rule {
                    id: "FIN-STATE-001".to_string(),
                    severity: AegisSeverity::Critical,
                    description: "Cumulative daily spend cannot exceed daily budget".to_string(),
                    suggested_fix: None,
                    condition: RuleCondition {
                        r#type: "state_invariant".to_string(),
                        params: r2_params,
                    },
                },
            ],
        }
    }

    pub fn default_data_guard() -> RulePack {
        let mut r1_params = HashMap::new();
        r1_params.insert(
            "patterns".to_string(),
            serde_json::json!([
                "CREDIT_CARD",
                "US_SSN",
                "US_TAX_ID",
                "DRIVER_LICENSE",
                "MEDICAL_RECORD_NUMBER",
                "US_NPI",
                "US_DEA"
            ]),
        );
        r1_params.insert("match_action".to_string(), serde_json::json!("block"));

        let mut r2_params = HashMap::new();
        r2_params.insert(
            "patterns".to_string(),
            serde_json::json!([
                "OPENAI_API_KEY",
                "GITHUB_TOKEN",
                "AWS_ACCESS_KEY",
                "STRIPE_KEY",
                "GENERIC_BEARER",
                "JWT_TOKEN",
                "SLACK_TOKEN",
                "SENDGRID_KEY",
                "AZURE_KEY",
                "PRIVATE_KEY",
                "SENSITIVE_FILE_PATH",
                "DESTRUCTIVE_COMMAND"
            ]),
        );
        r2_params.insert("match_action".to_string(), serde_json::json!("block"));

        RulePack {
            id: "data-guard".to_string(),
            name: "Aegis PII & Credential Leak Guard".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Detects and blocks leakage of credit cards, SSNs, cloud secrets, and API keys".to_string()),
            rules: vec![
                Rule {
                    id: "DATA-001".to_string(),
                    severity: AegisSeverity::Critical,
                    description: "Block credit cards, US Social Security numbers, Tax IDs, and Medical Records".to_string(),
                    suggested_fix: Some("Redact PII before calling external APIs.".to_string()),
                    condition: RuleCondition {
                        r#type: "regex".to_string(),
                        params: r1_params,
                    },
                },
                Rule {
                    id: "DATA-002".to_string(),
                    severity: AegisSeverity::Critical,
                    description: "Block API secret keys, cloud credentials, Slack tokens, and system paths".to_string(),
                    suggested_fix: Some("API keys and cloud credentials must not be passed in tool payload body.".to_string()),
                    condition: RuleCondition {
                        r#type: "regex".to_string(),
                        params: r2_params,
                    },
                },
            ],
        }
    }

    fn compute_policy_commitment(packs: &[RulePack]) -> String {
        let mut hasher = Sha256::new();
        let mut rule_keys = Vec::new();
        for p in packs {
            for r in &p.rules {
                rule_keys.push(format!("{}:{}:{:?}", p.id, r.id, r.severity));
            }
        }
        rule_keys.sort();

        for k in rule_keys {
            hasher.update(k.as_bytes());
            hasher.update(b"\0");
        }

        let digest = hasher.finalize();
        digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    pub fn evaluate(&self, call: &ToolCall) -> Verdict {
        self.evaluate_with_state(call, None)
    }

    pub fn evaluate_with_state(
        &self,
        call: &ToolCall,
        state_context: Option<&HashMap<String, serde_json::Value>>,
    ) -> Verdict {
        let start = Instant::now();
        let mut structured_violations: Vec<AegisViolation> = Vec::new();

        for rule in &self.compiled_rules {
            let v_list = match &rule.kind {
                CompiledRuleKind::Sql(sql_params) => self.sql_checker.evaluate(
                    &rule.id,
                    &rule.pack_id,
                    sql_params,
                    call,
                    rule.severity.clone(),
                ),
                CompiledRuleKind::Numeric(num_params) => self.numeric_checker.evaluate(
                    &rule.id,
                    &rule.pack_id,
                    num_params,
                    call,
                    rule.severity.clone(),
                ),
                CompiledRuleKind::Regex(regex_params) => self.pii_checker.evaluate(
                    &rule.id,
                    &rule.pack_id,
                    regex_params,
                    call,
                    rule.severity.clone(),
                ),
                CompiledRuleKind::State(state_params) => self.state_checker.evaluate(
                    &rule.id,
                    &rule.pack_id,
                    state_params,
                    call,
                    state_context,
                    rule.severity.clone(),
                ),
                CompiledRuleKind::Other => Vec::new(),
            };
            structured_violations.extend(v_list);
        }

        let has_critical = structured_violations
            .iter()
            .any(|v| v.severity == AegisSeverity::Critical);
        let mut allowed = !has_critical;
        if self.config.mode == AegisMode::Shadow {
            allowed = true;
        }

        let latency_us = start.elapsed().as_micros();

        let mut hasher = Sha256::new();
        hasher.update(call.name.as_bytes());
        hasher.update(allowed.to_string().as_bytes());
        hasher.update(self.policy_commitment_hash.as_bytes());
        hasher.update(&structured_violations.len().to_be_bytes());
        let proof_hash = hasher.finalize_hex();

        let violations: Vec<String> = structured_violations
            .iter()
            .map(|v| v.message.clone())
            .collect();
        let suggested_fix = structured_violations
            .iter()
            .find_map(|v| v.suggested_fix.clone());

        Verdict {
            allowed,
            violations,
            structured_violations,
            latency_us,
            proof_hash,
            suggested_fix,
            warning: None,
        }
    }
}
