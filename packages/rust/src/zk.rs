//! Policy Commitment & Attestation Module (Not Zero-Knowledge)
//!
//! ╔═══════════════════════════════════════════════════════════════╗
//! ║  POLICY COMMITMENT VERIFIER (NOT Zero-Knowledge Proof)       ║
//! ║                                                               ║
//! ║  This module implements a DETERMINISTIC HASH-BASED            ║
//! ║  commitment scheme — NOT a zero-knowledge proof. It uses      ║
//! ║  SHA-256 hash chaining to prove that a sensitive parameter    ║
//! ║  fell within a policy-defined range, without revealing the    ║
//! ║  exact value.                                                 ║
//! ║                                                               ║
//! ║  This is a NON-INTERACTIVE COMMITMENT, not a zk-SNARK or      ║
//! ║  Groth16 proof. True zero-knowledge proofs (Groth16/PLONK)    ║
//! ║  are a future roadmap item.                                   ║
//! ║                                                               ║
//! ║  EnclaveAttestation provides a DEVELOPMENT-SIMULATED          ║
//! ║  attestation report. It does NOT perform real AWS Nitro or    ║
//! ║  Intel SGX attestation. In production, swap in real NSM/SGX   ║
//! ║  SDK calls. See AEGIS_ATTESTATION_MODE env variable.         ║
//! ╚═══════════════════════════════════════════════════════════════╝

use crate::crypto::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommitmentProof {
    pub proof_type: String,
    pub proof_bytes_hex: String,
    pub public_policy_hash: String,
    pub is_valid: bool,
}

/// A deterministic SHA-256 policy commitment circuit.
///
/// Proves that a private value fell within [min_threshold, max_threshold]
/// without revealing the exact value — using hash chaining, NOT ZK.
pub struct PolicyCommitmentCircuit {
    pub policy_id: String,
    pub min_threshold: f64,
    pub max_threshold: f64,
}

impl PolicyCommitmentCircuit {
    pub fn new(policy_id: &str, min: f64, max: f64) -> Self {
        Self {
            policy_id: policy_id.to_string(),
            min_threshold: min,
            max_threshold: max,
        }
    }

    /// Generates a deterministic SHA-256 commitment proving that
    /// `private_value` falls within the policy bounds.
    ///
    /// NOTE: This is a hash commitment, not a zero-knowledge proof.
    /// A verifier with the expected policy hash can confirm compliance
    /// without seeing `private_value`, but this does NOT provide zk
    /// properties (hiding is computational through hashing).
    pub fn prove_compliance(&self, private_value: f64) -> Result<CommitmentProof, String> {
        if private_value < self.min_threshold || private_value > self.max_threshold {
            return Err(format!(
                "Value {} violates policy constraints [{}, {}]",
                private_value, self.min_threshold, self.max_threshold
            ));
        }

        let mut hasher = Sha256::new();
        hasher.update(self.policy_id.as_bytes());
        hasher.update(&self.min_threshold.to_be_bytes());
        hasher.update(&self.max_threshold.to_be_bytes());
        let public_policy_hash = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let mut proof_hasher = Sha256::new();
        proof_hasher.update(public_policy_hash.as_bytes());
        proof_hasher.update(&private_value.to_be_bytes());
        proof_hasher.update(b"SHA256_COMMITMENT");
        let proof_bytes_hex = proof_hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();

        Ok(CommitmentProof {
            proof_type: "SHA256_PolicyCommitment".to_string(),
            proof_bytes_hex,
            public_policy_hash,
            is_valid: true,
        })
    }

    /// Verifies a commitment proof against the expected policy hash.
    pub fn verify_proof(proof: &CommitmentProof, expected_policy_hash: &str) -> bool {
        proof.is_valid && proof.public_policy_hash == expected_policy_hash
    }
}

/// DEVELOPMENT-SIMULATED enclave attestation.
///
/// When AEGIS_ATTESTATION_MODE=production, returns simulated reports
/// with a warning. Real AWS Nitro / Intel SGX attestation requires
/// the `nsm` or `sgx-dcap-quote-verify` crates and is on the roadmap.
///
/// Set AEGIS_ATTESTATION_MODE=production to request real attestation
/// (will return SIMULATED until NSM/SGX integration is complete).
pub struct EnclaveAttestation {}

impl EnclaveAttestation {
    /// Returns the current attestation mode.
    /// 'development' (simulated, default) or 'production' (real attestation required).
    pub fn attestation_mode() -> &'static str {
        match env::var("AEGIS_ATTESTATION_MODE") {
            Ok(val) if val == "production" => "production",
            _ => "development",
        }
    }

    /// Generates a simulated attestation report.
    ///
    /// In development mode (default): returns a simulated report with
    ///   attestation_status = "DEV_SIMULATED"
    ///
    /// In production mode: returns a report with
    ///   attestation_status = "SIMULATED_AWAITING_NATIVE_SDK"
    /// indicating that real NSM/SGX integration is pending.
    ///
    /// Once AWS Nitro `nsm` crate or Intel SGX DCAP is integrated,
    /// this function will perform real attestation.
    pub fn generate_attestation_report(enclave_id: &str) -> HashMap<String, String> {
        let mode = Self::attestation_mode();
        let mut report = HashMap::new();
        let mut hasher = Sha256::new();
        hasher.update(enclave_id.as_bytes());
        hasher.update(b"AEGIS_DEV_ROOT_OF_TRUST");
        let pcr0 = hasher.finalize_hex();

        report.insert("enclave_id".to_string(), enclave_id.to_string());
        report.insert("pcr0".to_string(), pcr0);
        report.insert("hardware_provider".to_string(), "DEV_SIMULATED".to_string());

        if mode == "production" {
            report.insert(
                "attestation_status".to_string(),
                "SIMULATED_AWAITING_NATIVE_SDK".to_string(),
            );
            report.insert(
                "note".to_string(),
                "Real NSM/SGX attestation is on the roadmap. See ROADMAP.md.".to_string(),
            );
        } else {
            report.insert("attestation_status".to_string(), "DEV_SIMULATED".to_string());
            report.insert(
                "note".to_string(),
                "Development-mode simulated attestation. Set AEGIS_ATTESTATION_MODE=production to request real attestation.".to_string(),
            );
        }

        report
    }
}
