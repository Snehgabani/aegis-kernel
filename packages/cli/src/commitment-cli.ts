/**
 * @file packages/cli/src/commitment-cli.ts
 * @description CLI commands for cryptographic policy commitment proof generation and external auditor verification.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { PolicyCommitmentVerifier, type PolicyCommitmentConstraint } from '@aegis-kernel/core';

export function runPolicyProve(
  policyId: string,
  min: number,
  max: number,
  privateValue: number,
  options: { output?: string } = {}
): void {
  const constraint: PolicyCommitmentConstraint = {
    policyId,
    minAllowed: min,
    maxAllowed: max,
  };

  try {
    console.log(`\x1b[36m🔐 AEGIS CRYPTOGRAPHIC POLICY COMMITMENT GENERATOR\x1b[0m`);
    console.log(`Generating commitment proof for policy: \x1b[33m${policyId}\x1b[0m...`);

    const result = PolicyCommitmentVerifier.generateComplianceProof(constraint, privateValue);

    if (!result.success || !result.proof) {
      console.error(`\x1b[31mProof generation failed: ${result.error}\x1b[0m`);
      process.exitCode = 1;
      return;
    }

    const proof = result.proof;
    console.log(`\x1b[32m✔ Proof generated successfully!\x1b[0m`);
    console.log(`  • Policy ID:          ${proof.policyId}`);
    console.log(`  • Proof Type:         ${proof.proofType}`);
    console.log(`  • Public Policy Hash: ${proof.publicPolicyHash.substring(0, 16)}...`);
    console.log(`  • Proof Hash:         ${proof.proofBytesHex.substring(0, 16)}...`);

    if (options.output) {
      const outPath = path.resolve(process.cwd(), options.output);
      fs.writeFileSync(outPath, JSON.stringify(proof, null, 2), 'utf8');
      console.log(`\n\x1b[32m✔ Written proof artifact to: ${outPath}\x1b[0m`);
    }
  } catch (err: any) {
    console.error(`\x1b[31mProof generation failed: ${err?.message || err}\x1b[0m`);
    process.exitCode = 1;
  }
}

export function runPolicyVerify(
  proofPath: string,
  min: number,
  max: number
): void {
  const resolved = path.resolve(process.cwd(), proofPath);
  if (!fs.existsSync(resolved)) {
    console.error(`\x1b[31mError: Proof file not found at ${resolved}\x1b[0m`);
    process.exitCode = 1;
    return;
  }

  try {
    const content = fs.readFileSync(resolved, 'utf8');
    const proof = JSON.parse(content);

    const constraint: PolicyCommitmentConstraint = {
      policyId: proof.policyId,
      minAllowed: min,
      maxAllowed: max,
    };

    console.log(`\x1b[36m🔍 AEGIS EXTERNAL AUDITOR COMMITMENT VERIFIER\x1b[0m`);
    console.log(`Verifying proof artifact: \x1b[33m${path.basename(resolved)}\x1b[0m...`);

    const expectedHash = PolicyCommitmentVerifier.computePolicyHash(constraint);
    const isValid = PolicyCommitmentVerifier.verifyProof(proof, expectedHash);

    if (isValid) {
      console.log(`\n\x1b[32m✔ VERIFIED: Private parameter mathematically confirmed within bounds [$${min}, $${max}] without disclosure.\x1b[0m`);
    } else {
      console.error(`\n\x1b[31m❌ REJECTED: Cryptographic policy commitment proof is INVALID or tampered.\x1b[0m`);
      process.exitCode = 1;
    }
  } catch (err: any) {
    console.error(`\x1b[31mVerification failed: ${err?.message || err}\x1b[0m`);
    process.exitCode = 1;
  }
}
