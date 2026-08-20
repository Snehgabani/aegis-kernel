/**
 * @file packages/cli/src/pack-sign-cli.ts
 * @description `aegis pack sign|verify` — signed rule-pack manifests (AISVS C10.1.1).
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';
import pc from 'picocolors';
import {
  signPack,
  verifyPackAgainstTrustedKeys,
  type PackSignatureManifest,
} from '@aegis-kernel/core';
import { RulePackLoader } from '@aegis-kernel/core';
import type { RulePack } from '@aegis-kernel/core';

function loadPackFile(filePath: string): RulePack | null {
  const content = fs.readFileSync(path.resolve(filePath), 'utf8');
  const parsed = filePath.endsWith('.json') ? JSON.parse(content) : yaml.parse(content);
  if (!RulePackLoader.validatePack(parsed)) return null;
  return parsed as RulePack;
}

export function runPackSign(filePath: string, keyPath: string, signer?: string): void {
  try {
    const pack = loadPackFile(filePath);
    if (!pack) {
      console.log(pc.red('❌ Pack failed schema validation; refusing to sign.'));
      process.exitCode = 1;
      return;
    }
    const privateKeyPem = fs.readFileSync(path.resolve(keyPath), 'utf8');
    const manifest = signPack(pack, privateKeyPem, signer);
    const outPath = filePath + '.sig.json';
    fs.writeFileSync(path.resolve(outPath), JSON.stringify(manifest, null, 2), 'utf8');
    console.log(pc.green(`✅ Signed '${pack.id}' v${pack.version}`));
    console.log(`  Manifest:  ${pc.bold(outPath)}`);
    console.log(`  Commitment: ${manifest.commitment.slice(0, 32)}…`);
    console.log(pc.dim(`  Distribute the public key out-of-band; verification is fail-closed.`));
  } catch (err) {
    console.log(pc.red(`❌ Signing failed: ${(err as Error).message}`));
    process.exitCode = 1;
  }
}

export function runPackVerify(filePath: string, publicKeyPaths: string[]): void {
  try {
    const pack = loadPackFile(filePath);
    if (!pack) {
      console.log(pc.red('❌ Pack failed schema validation.'));
      process.exitCode = 1;
      return;
    }
    const manifestPath = filePath + '.sig.json';
    if (!fs.existsSync(path.resolve(manifestPath))) {
      console.log(pc.red(`❌ No signature manifest found at ${manifestPath}`));
      console.log(pc.dim('  Unsigned packs are not verified by default; sign with `aegis pack sign`.'));
      process.exitCode = 1;
      return;
    }
    const manifest = JSON.parse(fs.readFileSync(path.resolve(manifestPath), 'utf8')) as PackSignatureManifest;
    const trustedKeys = publicKeyPaths.map((p) => fs.readFileSync(path.resolve(p), 'utf8'));
    const result = verifyPackAgainstTrustedKeys(pack, manifest, trustedKeys);
    if (result.valid) {
      console.log(pc.green(`✅ Signature VALID for '${pack.id}' v${pack.version}`));
      console.log(`  Commitment: ${result.commitment.slice(0, 32)}…`);
      console.log(`  Signed by:  ${manifest.signer ?? 'unknown'} at ${manifest.signedAt}`);
    } else {
      console.log(pc.red(`❌ Signature verification FAILED for '${pack.id}' v${pack.version}:`));
      for (const e of result.errors) console.log(pc.red(`  • ${e}`));
      process.exitCode = 1;
    }
  } catch (err) {
    console.log(pc.red(`❌ Verification error: ${(err as Error).message}`));
    process.exitCode = 1;
  }
}
