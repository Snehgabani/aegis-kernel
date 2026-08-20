use aegis_kernel::{
    AegisEngine, CommitmentProof, Config, EnclaveAttestation, PiiTokenVault, PolicyCommitmentCircuit,
    Rule, RuleCondition, RulePack, ToolCall, AegisSeverity,
};
use serde_json::json;
use std::collections::HashMap;

#[test]
fn test_evaluate() {
    let mut numeric_limits = HashMap::new();
    numeric_limits.insert("amount".to_string(), (0.0, 1000.0));

    let mut cfg = Config::default();
    cfg.enable_sql_validation = true;
    cfg.enable_pii_scanning = true;
    cfg.numeric_limits = numeric_limits;
    let engine = AegisEngine::new(cfg);

    let mut args = HashMap::new();
    args.insert("query".to_string(), json!("SELECT * FROM users WHERE id = 1"));
    let call = ToolCall::new("get_data", args);

    let verdict = engine.evaluate(&call);
    assert!(verdict.allowed);
    assert!(!verdict.proof_hash.is_empty());

    let mut args2 = HashMap::new();
    args2.insert("query".to_string(), json!("DROP TABLE users"));
    let call2 = ToolCall::new("get_data", args2);

    let verdict2 = engine.evaluate(&call2);
    assert!(!verdict2.allowed);
    assert!(verdict2.violations.iter().any(|v| v.contains("prohibited") || v.contains("DROP") || v.contains("Destructive")));
}

#[test]
fn test_sql_invariants_and_tautologies() {
    let engine = AegisEngine::new_default();

    // 1. Valid queries
    let valid_queries = vec![
        ("db_query", "query", "SELECT id, name FROM users WHERE id = 42"),
        ("run_sql", "sql", "SELECT * FROM orders WHERE status = 'pending' LIMIT 100"),
        ("custom_tool", "stmt", "INSERT INTO logs (msg) VALUES ('test user login')"),
        ("search_kb", "query", "how to delete a record in react"), // Search tool query should be allowed
    ];
    for (tool, param, q) in valid_queries {
        let mut args = HashMap::new();
        args.insert(param.to_string(), json!(q));
        let call = ToolCall::new(tool, args);
        let verdict = engine.evaluate(&call);
        assert!(verdict.allowed, "Expected valid query to be allowed: {}, violations: {:?}", q, verdict.violations);
    }

    // 2. DDL Attacks
    let ddl_attacks = vec![
        "DROP TABLE users",
        "DROP DATABASE production",
        "TRUNCATE TABLE transactions",
        "ALTER TABLE users DROP COLUMN password_hash",
        "GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'",
        "REVOKE ALL ON users FROM admin",
    ];
    for q in ddl_attacks {
        let mut args = HashMap::new();
        args.insert("query".to_string(), json!(q));
        let call = ToolCall::new("db_query", args);
        let verdict = engine.evaluate(&call);
        assert!(!verdict.allowed, "Expected DDL query '{}' to be blocked", q);
    }

    // 3. Mass DELETE and UPDATE without WHERE
    let mass_mutations = vec![
        "DELETE FROM users",
        "UPDATE users SET role = 'admin'",
    ];
    for q in mass_mutations {
        let mut args = HashMap::new();
        args.insert("query".to_string(), json!(q));
        let call = ToolCall::new("db_query", args);
        let verdict = engine.evaluate(&call);
        assert!(!verdict.allowed, "Expected mass mutation '{}' to be blocked", q);
    }

    // 4. Tautology Evasion Vectors
    let tautology_queries = vec![
        "DELETE FROM users WHERE 1=1",
        "DELETE FROM users WHERE 1 = 1",
        "DELETE FROM users WHERE 2=2",
        "DELETE FROM users WHERE 0=0",
        "DELETE FROM users WHERE 100=100",
        "DELETE FROM users WHERE 2>1",
        "DELETE FROM users WHERE 10>5",
        "DELETE FROM users WHERE 'a'='a'",
        "DELETE FROM users WHERE TRUE",
        "DELETE FROM users WHERE 1",
        "DELETE FROM users WHERE id = id",
        "DELETE FROM users WHERE users.id = users.id",
        "DELETE FROM users WHERE id IS NOT NULL",
        "DELETE FROM users WHERE id > 0",
        "DELETE FROM users WHERE id >= 0",
        "DELETE FROM users WHERE id != -1",
        "DELETE FROM users WHERE id <> -1",
        "DELETE FROM users WHERE id = 123 OR 1=1",
        "DELETE FROM users WHERE id = 'abc' OR TRUE",
        "DELETE FROM users WHERE id IN (SELECT id FROM users)",
    ];
    for q in tautology_queries {
        let mut args = HashMap::new();
        args.insert("query".to_string(), json!(q));
        let call = ToolCall::new("db_query", args);
        let verdict = engine.evaluate(&call);
        assert!(!verdict.allowed, "Expected tautology '{}' to be blocked", q);
    }

    // 5. Comment and CTE Evasions
    let comment_evasions = vec![
        "DEL/**/ETE FROM users WHERE 1=1",
        "D/**/R/**/O/**/P TABLE users",
        "D R O P TABLE users",
        "\\x44\\x52\\x4F\\x50 TABLE users",
        "'DEL' || 'ETE' FROM users",
        "WITH cte AS (DELETE FROM users WHERE 1=1) SELECT * FROM cte",
    ];
    for q in comment_evasions {
        let mut args = HashMap::new();
        args.insert("query".to_string(), json!(q));
        let call = ToolCall::new("db_query", args);
        let verdict = engine.evaluate(&call);
        assert!(!verdict.allowed, "Expected comment evasion '{}' to be blocked", q);
    }
}

#[test]
fn test_numeric_invariants_and_aliases() {
    let engine = AegisEngine::new_default();

    // 1. Valid amount $500
    let mut args1 = HashMap::new();
    args1.insert("amount".to_string(), json!(500.0));
    let v1 = engine.evaluate(&ToolCall::new("payout", args1));
    assert!(v1.allowed);

    // 2. Amount exceeding $10k limit
    let mut args2 = HashMap::new();
    args2.insert("amount".to_string(), json!(25000.0));
    let v2 = engine.evaluate(&ToolCall::new("payout", args2));
    assert!(!v2.allowed);

    // 3. Formatted currency string stripping: "$15,000.00 USD" -> 15000.0 (exceeds $10k)
    let mut args3 = HashMap::new();
    args3.insert("amount".to_string(), json!("$15,000.00 USD"));
    let v3 = engine.evaluate(&ToolCall::new("transfer", args3));
    assert!(!v3.allowed);

    // 4. Euro currency: "€ 5,000.00" -> 5000.0 (allowed)
    let mut args4 = HashMap::new();
    args4.insert("amount".to_string(), json!("€ 5,000.00"));
    let v4 = engine.evaluate(&ToolCall::new("transfer", args4));
    assert!(v4.allowed);

    // 5. Semantic alias detection: "payout: 50000"
    let mut args5 = HashMap::new();
    args5.insert("payout".to_string(), json!(50000.0));
    let v5 = engine.evaluate(&ToolCall::new("execute_payment", args5));
    assert!(!v5.allowed);

    // 6. Negative amount on financial alias (default min: 0)
    let mut args6 = HashMap::new();
    args6.insert("amount".to_string(), json!(-50.0));
    let v6 = engine.evaluate(&ToolCall::new("transfer", args6));
    assert!(!v6.allowed);
}

#[test]
fn test_pii_and_secrets_scanning() {
    let engine = AegisEngine::new_default();

    let pii_cases = vec![
        ("US SSN", "send_email", "body", "Customer SSN is 123-45-6789"),
        ("OpenAI Key", "api_call", "token", "sk-proj-abcdef1234567890abcdef123456"),
        ("GitHub Token", "github_sync", "key", "ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
        ("AWS Key", "s3_upload", "aws_key", "AKIAIOSFODNN7EXAMPLE"),
        ("Slack Token", "post_slack", "auth", "xoxb-1234567890-abcdef12345"),
        ("Sensitive Path", "read_file", "path", "/etc/shadow"),
        ("Destructive Command", "run_shell", "cmd", "rm -rf /"),
    ];

    for (name, tool, param, val) in pii_cases {
        let mut args = HashMap::new();
        args.insert(param.to_string(), json!(val));
        let call = ToolCall::new(tool, args);
        let verdict = engine.evaluate(&call);
        assert!(!verdict.allowed, "[{}] Expected PII/Secret to be blocked: {:?}", name, call);
    }
}

#[test]
fn test_salted_pii_token_vault() {
    let mut vault = PiiTokenVault::new(None, None, None);
    let raw_text = "User john (SSN: 123-45-6789, email: john@example.com) uploaded token sk-proj-1234567890abcdefghij";

    let tokenized = vault.tokenize(raw_text);
    assert!(tokenized.tokens_created > 0);
    assert!(!tokenized.sanitized.contains("123-45-6789"));
    assert!(!tokenized.sanitized.contains("sk-proj-1234567890abcdefghij"));

    let detokenized = vault.detokenize(&tokenized.sanitized);
    assert_eq!(detokenized.restored, raw_text);
}

#[test]
fn test_state_invariants_and_tenant_isolation() {
    let engine = AegisEngine::new_default();

    let mut state = HashMap::new();
    state.insert("tenant_id".to_string(), json!("org_123"));
    state.insert("account_status".to_string(), json!("active"));
    state.insert("spent_today".to_string(), json!(4000.0));
    state.insert("daily_budget".to_string(), json!(5000.0));

    // 1. Valid budget spend (4000 + 500 <= 5000)
    let mut args1 = HashMap::new();
    args1.insert("amount".to_string(), json!(500.0));
    let call1 = ToolCall::new("spend_budget", args1);
    let v1 = engine.evaluate_with_state(&call1, Some(&state));
    assert!(v1.allowed);

    // 2. Over budget spend (4000 + 1500 > 5000)
    let mut args2 = HashMap::new();
    args2.insert("amount".to_string(), json!(1500.0));
    let call2 = ToolCall::new("spend_budget", args2);
    let v2 = engine.evaluate_with_state(&call2, Some(&state));
    assert!(!v2.allowed);

    // 3. Cross-tenant isolation violation
    let mut tenant_rule_params = HashMap::new();
    tenant_rule_params.insert("tenant_field".to_string(), json!("tenant_id"));
    let tenant_pack = RulePack {
        id: "tenant-pack".to_string(),
        name: "Tenant Isolation Guard".to_string(),
        version: "1.0.0".to_string(),
        description: None,
        rules: vec![
            Rule {
                id: "TENANT-001".to_string(),
                severity: AegisSeverity::Critical,
                description: "Tenant isolation check".to_string(),
                suggested_fix: None,
                condition: RuleCondition {
                    r#type: "state_invariant".to_string(),
                    params: tenant_rule_params,
                },
            },
        ],
    };

    let tenant_engine = AegisEngine::new_with_packs(vec![tenant_pack]);
    let mut attacker_args = HashMap::new();
    attacker_args.insert("tenant_id".to_string(), json!("org_attacker"));
    let attacker_call = ToolCall::new("fetch_data", attacker_args);

    let v3 = tenant_engine.evaluate_with_state(&attacker_call, Some(&state));
    assert!(!v3.allowed);
}

#[test]
fn test_zk_policy_circuit() {
    let circuit = PolicyCommitmentCircuit::new("policy_max_wire_transfer_10k", 0.0, 10000.0);

    // Compliant proof generation ($5,000 <= $10,000)
    let proof_res = circuit.prove_compliance(5000.0);
    assert!(proof_res.is_ok());
    let proof = proof_res.unwrap();
    assert_eq!(proof.proof_type, "SHA256_PolicyCommitment");
    assert!(!proof.proof_bytes_hex.is_empty());
    assert!(PolicyCommitmentCircuit::verify_proof(&proof, &proof.public_policy_hash));

    // Non-compliant proof generation ($50,000 > $10,000) -> Rejected
    let non_compliant = circuit.prove_compliance(50000.0);
    assert!(non_compliant.is_err());
}

#[test]
fn test_enclave_attestation() {
    // Temporarily set development mode for testing (default if unset)
    let report = EnclaveAttestation::generate_attestation_report("enclave_nitro_prod_01");
    assert_eq!(report.get("enclave_id").unwrap(), "enclave_nitro_prod_01");
    // In development mode (default), attestation is simulated
    assert_eq!(report.get("attestation_status").unwrap(), "DEV_SIMULATED");
    assert!(report.contains_key("pcr0"));
    assert!(report.contains_key("note"));
}
