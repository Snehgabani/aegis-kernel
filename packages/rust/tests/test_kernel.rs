use aegis_kernel::{AegisEngine, Config, ToolCall};
use std::collections::HashMap;
use serde_json::json;

#[test]
fn test_evaluate() {
    let mut numeric_limits = HashMap::new();
    numeric_limits.insert("amount".to_string(), (0.0, 1000.0));

    let engine = AegisEngine::new(Config {
        enable_sql_validation: true,
        enable_pii_scanning: true,
        numeric_limits,
    });

    let mut args = HashMap::new();
    args.insert("query".to_string(), json!("SELECT * FROM users"));
    let call = ToolCall {
        name: "get_data".to_string(),
        arguments: args,
    };

    let verdict = engine.evaluate(&call);
    assert!(verdict.allowed);
    assert!(!verdict.proof_hash.is_empty());

    let mut args2 = HashMap::new();
    args2.insert("query".to_string(), json!("DROP TABLE users"));
    let call2 = ToolCall {
        name: "get_data".to_string(),
        arguments: args2,
    };

    let verdict2 = engine.evaluate(&call2);
    assert!(!verdict2.allowed);
    assert!(verdict2.violations.contains(&"destructive SQL operation not allowed".to_string()));
}
