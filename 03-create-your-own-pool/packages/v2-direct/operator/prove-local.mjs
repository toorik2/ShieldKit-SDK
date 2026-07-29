/**
 * Operator-path real Groth16 prove for V2 Direct actions (depth-32 circuit).
 * No mock proofs. Used by CLI and live scripts.
 */
import { existsSync, mkdirSync, writeFileSync, copyFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CIRCUIT_TREE_DEPTH } from '../prove/witness.mjs';
import { proveActionV2, verifyActionV2 } from '../prove/prove.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
// operator/ → v2-direct → packages → 03-create-your-own-pool → worktree
const REPO_ROOT = path.resolve(here, '../../../../');
const DEFAULT_ARTIFACT = path.join(REPO_ROOT, '.cache/v2-direct-circuit');

export class OperatorProveError extends Error {
  constructor(message) {
    super(message);
    this.name = 'OperatorProveError';
  }
}

export function resolveCircuitArtifacts(artifactDir = process.env.V2_CIRCUIT_DIR || DEFAULT_ARTIFACT) {
  const zkeyPath = path.join(artifactDir, 'circuit_final.zkey');
  const wasmPath = path.join(artifactDir, 'circuit.wasm');
  const verificationKeyPath = path.join(artifactDir, 'verification_key.json');
  if (!existsSync(zkeyPath) || !existsSync(wasmPath) || !existsSync(verificationKeyPath)) {
    throw new OperatorProveError(
      `circuit artifacts missing under ${artifactDir} (need circuit_final.zkey, circuit.wasm, verification_key.json)`,
    );
  }
  return Object.freeze({ artifactDir, zkeyPath, wasmPath, verificationKeyPath, treeDepth: CIRCUIT_TREE_DEPTH });
}

/**
 * Prove + verify a pool engine action with expanded witness.
 * @returns {{ proof, publicSignals, publicInputs, packetDigest, treeDepth, ms }}
 */
export async function provePoolAction({
  packetBytes,
  expanded,
  artifactDir,
  workDir,
}) {
  const arts = resolveCircuitArtifacts(artifactDir);
  if (!expanded?.note || !expanded?.path) {
    throw new OperatorProveError('expanded.note and expanded.path required for real prove');
  }
  if (expanded.path.siblings?.length !== CIRCUIT_TREE_DEPTH) {
    throw new OperatorProveError(
      `path depth ${expanded.path.siblings?.length} != CIRCUIT_TREE_DEPTH ${CIRCUIT_TREE_DEPTH}`,
    );
  }
  const t0 = Date.now();
  const proved = await proveActionV2({
    packetBytes,
    zkeyPath: arts.zkeyPath,
    wasmPath: arts.wasmPath,
    expanded,
  });
  await verifyActionV2({
    proof: proved.proof,
    publicSignals: proved.publicSignals,
    verificationKeyPath: arts.verificationKeyPath,
  });
  if (workDir) {
    mkdirSync(workDir, { recursive: true });
    copyFileSync(arts.verificationKeyPath, path.join(workDir, 'verification_key.json'));
    writeFileSync(path.join(workDir, 'proof.json'), `${JSON.stringify({
      protocol: 'groth16',
      curve: 'bn128',
      pi_a: proved.proof.pi_a,
      pi_b: proved.proof.pi_b,
      pi_c: proved.proof.pi_c,
    }, null, 2)}\n`);
    writeFileSync(path.join(workDir, 'public.json'), `${JSON.stringify(proved.publicSignals.map(String))}\n`);
    writeFileSync(path.join(workDir, 'action.packet'), packetBytes);
  }
  return Object.freeze({
    proof: proved.proof,
    publicSignals: proved.publicSignals,
    publicInputs: proved.publicInputs,
    treeDepth: CIRCUIT_TREE_DEPTH,
    ms: Date.now() - t0,
  });
}

export { CIRCUIT_TREE_DEPTH };
