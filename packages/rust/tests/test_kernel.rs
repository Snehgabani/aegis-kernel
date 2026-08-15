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

#[test]
fn test_zk_policy_circuit() {
    use aegis_kernel::ZkPolicyCircuit;

    let circuit = ZkPolicyCircuit::new("policy_max_wire_transfer_10k", 0.0, 10000.0);
    
    // Compliant proof generation ($5,000 <= $10,000)
    let proof_res = circuit.prove_compliance(5000.0);
    assert!(proof_res.is_ok());
    let proof = proof_res.unwrap();
    assert_eq!(proof.proof_type, "Plonky3_Recursive_SNARK");
    assert!(!proof.proof_bytes_hex.is_empty());
    assert!(ZkPolicyCircuit::verify_proof(&proof, &proof.public_policy_hash));

    // Non-compliant proof generation ($50,000 > $10,000) -> Rejected
    let non_compliant = circuit.prove_compliance(50000.0);
    assert!(non_compliant.is_err());
}

#[test]
fn test_enclave_attestation() {
    use aegis_kernel::EnclaveAttestation;

    let report = EnclaveAttestation::generate_attestation_report("enclave_nitro_prod_01");
    assert_eq!(report.get("enclave_id").unwrap(), "enclave_nitro_prod_01");
    assert_eq!(report.get("attestation_status").unwrap(), "VALID_VERIFIED");
    assert!(report.contains_key("pcr0"));
}
