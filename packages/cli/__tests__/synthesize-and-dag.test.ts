import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runSynthesize } from '../src/synthesize-cli.js';
import { runDagTrace } from '../src/dag-trace-cli.js';
import { runPolicyProve, runPolicyVerify } from '../src/commitment-cli.js';

describe('Aegis CLI Synthesize, DAG Trace & Policy Commitment Suite', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-cli-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('synthesizes a RulePack from an MCP tool JSON schema', () => {
    const schemaFile = path.join(tmpDir, 'tool-schema.json');
    const outFile = path.join(tmpDir, 'synthesized-pack.json');

    fs.writeFileSync(
      schemaFile,
      JSON.stringify({
        name: 'transfer_funds',
        description: 'Execute bank wire transfer',
        inputSchema: {
          type: 'object',
          properties: {
            amount: { type: 'number', minimum: 1, maximum: 5000 },
            currency: { type: 'string', enum: ['USD', 'EUR', 'GBP'] },
          },
          required: ['amount', 'currency'],
        },
      })
    );

    runSynthesize(schemaFile, { output: outFile });
    expect(fs.existsSync(outFile)).toBe(true);

    const generated = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    expect(generated.id).toBe('synthesized_transfer_funds');
    expect(generated.rules.length).toBeGreaterThan(0);
  });

  it('renders an Execution DAG trace to output file', () => {
    const dagFile = path.join(tmpDir, 'dag.json');
    const outFile = path.join(tmpDir, 'trace.mmd');

    fs.writeFileSync(
      dagFile,
      JSON.stringify({
        actions: [
          { id: '1', agentId: 'ag1', actionType: 'read_db', timestamp: 1, securityLabel: { confidentiality: 'secret', integrity: 'trusted' } },
          { id: '2', agentId: 'ag1', actionType: 'http_post', timestamp: 2 }
        ],
        edges: [
          { sourceId: '1', targetId: '2', type: 'data_flow' }
        ]
      })
    );

    runDagTrace(dagFile, { format: 'mermaid', output: outFile });
    expect(fs.existsSync(outFile)).toBe(true);

    const content = fs.readFileSync(outFile, 'utf8');
    expect(content).toContain('flowchart TD');
    expect(content).toContain('read_db (1) [SECRET]');
  });

  it('generates and verifies cryptographic policy commitment proof artifacts', () => {
    const proofFile = path.join(tmpDir, 'proof.json');

    // Generate proof: policyId='WIRE_TRANSFER_MAX_5000', min=1, max=5000, value=2500
    runPolicyProve('WIRE_TRANSFER_MAX_5000', 1, 5000, 2500, { output: proofFile });
    expect(fs.existsSync(proofFile)).toBe(true);

    const proof = JSON.parse(fs.readFileSync(proofFile, 'utf8'));
    expect(proof.policyId).toBe('WIRE_TRANSFER_MAX_5000');
    expect(proof.proofBytesHex).toBeDefined();

    // Verify proof
    expect(() => runPolicyVerify(proofFile, 1, 5000)).not.toThrow();
  });
});
