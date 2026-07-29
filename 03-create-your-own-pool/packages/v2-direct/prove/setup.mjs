/**
 * Development-only Groth16 setup for PoolActionV2Direct.
 * Uses circom2 + snarkjs + hermez ptau (or powers-of-tau download).
 */
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import {
  existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const circuitSource = path.join(here, 'circuit', 'PoolActionV2Direct.circom');

export class V2SetupError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2SetupError';
  }
}

const fail = (m) => {
  throw new V2SetupError(m);
};

function sha256File(filePath) {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}

async function run(cmd, args, opts = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      maxBuffer: 64 * 1024 * 1024,
      ...opts,
    });
    return { stdout, stderr };
  } catch (error) {
    fail(`${cmd} ${args.join(' ')} failed: ${error.stderr || error.message}`);
  }
}

/**
 * Build circuit artifacts into outDir.
 * Requires ptauPath pointing to a powersOfTau file with enough capacity (power >= 12).
 */
export async function setupPoolActionV2DirectDevelopment({
  outDir,
  ptauPath,
  entropy = 'shieldkit-v2-direct-dev-entropy-v1',
}) {
  mkdirSync(outDir, { recursive: true });
  if (!existsSync(circuitSource)) fail('circuit source missing');
  if (!existsSync(ptauPath)) fail(`ptau missing: ${ptauPath}`);

  const circomCli = fileURLToPath(await import.meta.resolve('circom2/cli.js'));
  const snarkRoot = path.dirname(fileURLToPath(await import.meta.resolve('snarkjs')));
  const snarkCli = path.join(snarkRoot, 'build', 'cli.cjs');

  const compiled = path.join(outDir, 'compiled');
  mkdirSync(compiled, { recursive: true });

  // prove/ → v2-direct → packages → 03-create-your-own-pool → worktree root
  const repoRoot = path.resolve(here, '../../../..');
  const includeCandidates = [
    path.join(repoRoot, 'node_modules'),
    path.join(here, '../node_modules'),
    path.join(repoRoot, '03-create-your-own-pool/packages/v2-direct/node_modules'),
  ];
  const includeArgs = [];
  for (const inc of includeCandidates) {
    const poseidon = path.join(inc, 'circomlib/circuits/poseidon.circom');
    const circuits = path.join(inc, 'circomlib/circuits');
    if (existsSync(poseidon)) {
      // bare includes inside circomlib (montgomery.circom, etc.) need circuits dir
      includeArgs.push('-l', inc, '-l', circuits);
      break;
    }
    if (existsSync(path.join(inc, 'poseidon.circom'))) {
      includeArgs.push('-l', inc);
      break;
    }
  }
  if (!includeArgs.length) fail('circomlib not found in node_modules');
  await run(process.execPath, [
    circomCli, circuitSource, '--r1cs', '--wasm', '--sym', '-o', compiled, '--O0',
    ...includeArgs,
  ], { cwd: outDir });

  const r1cs = path.join(compiled, 'PoolActionV2Direct.r1cs');
  const wasm = path.join(compiled, 'PoolActionV2Direct_js', 'PoolActionV2Direct.wasm');
  if (!existsSync(r1cs) || !existsSync(wasm)) {
    // circom2 may place wasm differently
    const altWasm = path.join(compiled, 'PoolActionV2Direct.wasm');
    if (!existsSync(r1cs)) fail('r1cs not produced');
    if (!existsSync(wasm) && !existsSync(altWasm)) fail('wasm not produced');
  }

  const zkey0 = path.join(outDir, 'circuit_0000.zkey');
  const zkey1 = path.join(outDir, 'circuit_final.zkey');
  const vkeyPath = path.join(outDir, 'verification_key.json');

  await run(process.execPath, [snarkCli, 'groth16', 'setup', r1cs, ptauPath, zkey0], { cwd: outDir });
  await run(process.execPath, [
    snarkCli, 'zkey', 'contribute', zkey0, zkey1, `-e=${entropy}`,
  ], { cwd: outDir });
  await run(process.execPath, [snarkCli, 'zkey', 'export', 'verificationkey', zkey1, vkeyPath], {
    cwd: outDir,
  });

  // Resolve wasm path
  let wasmPath = wasm;
  if (!existsSync(wasmPath)) {
    wasmPath = path.join(compiled, 'PoolActionV2Direct.wasm');
  }
  const wasmDest = path.join(outDir, 'circuit.wasm');
  copyFileSync(wasmPath, wasmDest);

  // Parse constraint count from snarkjs if available (best-effort).
  let constraints = null;
  let treeDepth = 32;
  try {
    const { stdout } = await execFileAsync(process.execPath, [snarkCli, 'r1cs', 'info', r1cs], {
      maxBuffer: 16 * 1024 * 1024,
    });
    const m = /# of Constraints:\s*(\d+)/i.exec(stdout);
    if (m) constraints = Number(m[1]);
  } catch {
    // ignore
  }
  try {
    const src = readFileSync(circuitSource, 'utf8');
    const dm = /PoolActionV2Direct\((\d+)\)/.exec(src);
    if (dm) treeDepth = Number(dm[1]);
  } catch {
    // ignore
  }

  const manifest = {
    schema: 'shield.cash/v2-direct-dev-setup/v1',
    mode: 'development-only',
    relationId: 'pool-action-v2-direct',
    treeDepth,
    constraints,
    features: {
      noteMerkle: true,
      indexedNullifierInsert: true,
      recordCommitmentSponge: true,
      babyJubEncryption: true,
    },
    artifacts: {
      r1cs: path.relative(outDir, r1cs),
      zkey: 'circuit_final.zkey',
      verificationKey: 'verification_key.json',
      wasm: 'circuit.wasm',
    },
    hashes: {
      r1cs: `sha256:${sha256File(r1cs)}`,
      zkey: `sha256:${sha256File(zkey1)}`,
      verificationKey: `sha256:${sha256File(vkeyPath)}`,
      wasm: `sha256:${sha256File(wasmDest)}`,
      circuitSource: `sha256:${sha256File(circuitSource)}`,
    },
  };
  writeFileSync(path.join(outDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return Object.freeze({
    outDir,
    r1cs,
    zkey: zkey1,
    verificationKey: vkeyPath,
    wasm: wasmDest,
    manifest,
  });
}

export function defaultArtifactDir() {
  return path.resolve(here, '../../../.cache/v2-direct-circuit');
}
