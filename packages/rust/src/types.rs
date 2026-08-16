use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AegisMode {
    Enforce,
    Shadow,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AegisSeverity {
    Critical,
    Warning,
    Info,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AegisFailPolicy {
    FailClosed,
    FailOpen,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: HashMap<String, serde_json::Value>,
}

impl ToolCall {
    pub fn new(name: impl Into<String>, arguments: HashMap<String, serde_json::Value>) -> Self {
        Self {
            name: name.into(),
            arguments,
        }
    }

    pub fn get_tool_name(&self) -> &str {
        &self.name
    }

    pub fn get_arguments(&self) -> &HashMap<String, serde_json::Value> {
        &self.arguments
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AegisViolation {
    pub rule_id: String,
    pub pack_id: String,
    pub severity: AegisSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Verdict {
    pub allowed: bool,
    pub violations: Vec<String>,
    #[serde(default)]
    pub structured_violations: Vec<AegisViolation>,
    pub latency_us: u128,
    pub proof_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuleCondition {
    pub r#type: String, // "sql_ast", "numeric", "regex", "state_invariant"
    pub params: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub severity: AegisSeverity,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fix: Option<String>,
    pub condition: RuleCondition,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RulePack {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub rules: Vec<Rule>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SqlAstConditionParams {
    #[serde(default)]
    pub statements: Vec<String>,
    #[serde(default)]
    pub block_statements: Vec<String>,
    pub require: Option<String>,
    pub max_limit: Option<i64>,
    pub database_field: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RateLimit {
    pub max_per_minute: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NumericConditionParams {
    pub field: String,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub rate_limit: Option<RateLimit>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegexConditionParams {
    pub patterns: Vec<String>,
    pub match_action: Option<String>, // "block" | "warn"
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StateInvariantConditionParams {
    pub target_field: Option<String>,
    pub tenant_field: Option<String>,
    #[serde(default)]
    pub require_state: bool,
    pub precondition: Option<String>,
    pub assertion: String,
}

pub struct Config {
    pub enable_sql_validation: bool,
    pub enable_pii_scanning: bool,
    pub numeric_limits: HashMap<String, (f64, f64)>,
    pub mode: AegisMode,
    pub fail_policy: AegisFailPolicy,
    pub rule_packs: Vec<RulePack>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enable_sql_validation: true,
            enable_pii_scanning: true,
            numeric_limits: HashMap::new(),
            mode: AegisMode::Enforce,
            fail_policy: AegisFailPolicy::FailClosed,
            rule_packs: Vec::new(),
        }
    }
}
