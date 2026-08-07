// ShieldKit-Groth-54KB — pf6 proving pipeline (rapidsnark native + snarkjs witness).
// Circuit: current product main-chipnet (r1cs 077f58f5 / wasm 87f5878e / zkey 61683ef2).
'use strict';

import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

export const PF6_PROVE_SCHEMA = 'shieldkit-v2-direct-pf6-prove-v1';

export class Pf6ProveError extends Error {
  constructor(code, message) { super(message); this.name = 'Pf6ProveError'; this.code = code; }
}

export function proveGroth16({ zkeyPath, wasmPath, circuitInputPath, outDir, proverBin, snarkjsCli }) {
  if (!existsSync(zkeyPath)) throw new Pf6ProveError('ZKEY', `missing ${zkeyPath}`);
  if (!existsSync(wasmPath)) throw new Pf6ProveError('WASM', `missing ${wasmPath}`);
  if (!existsSync(circuitInputPath)) throw new Pf6ProveError('INPUT', `missing ${circuitInputPath}`);
  const witnessPath = path.join(outDir, 'witness.wtns');
  const proofPath = path.join(outDir, 'proof.json');
  const publicPath = path.join(outDir, 'public.json');

  // 1) witness (snarkjs wtns calculate)
  const wtns = spawnSync('node', [snarkjsCli, 'wtns', 'calculate', wasmPath, circuitInputPath, witnessPath],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (wtns.status !== 0) throw new Pf6ProveError('WITNESS', `snarkjs wtns failed: ${(wtns.stderr || wtns.stdout).slice(0, 500)}`);

  // 2) prove (rapidsnark native)
  const pr = spawnSync(proverBin, [zkeyPath, witnessPath, proofPath, publicPath],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (pr.status !== 0) throw new Pf6ProveError('PROVE', `rapidsnark failed: ${(pr.stderr || pr.stdout).slice(0, 500)}`);
  if (!existsSync(proofPath) || !existsSync(publicPath)) throw new Pf6ProveError('OUTPUT', 'prove did not emit proof/public');

  return Object.freeze({
    schema: PF6_PROVE_SCHEMA,
    proofPath, publicPath, witnessPath,
    proofSha256: null, // set by caller after read
  });
}
