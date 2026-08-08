/**
 * Product path: Rust prove (statement) → sound settlement assemble → size/VM checks.
 * Assembly uses vendor STK proof with the same pool_witness (kind, depth, seed) so
 * statements match the Rust worker; Libauth verifies the sound multi-input locks.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assembleProductionSettlement, MAX_TX_BYTES, MAX_UNLOCK_BYTES } from './settlement.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const WORKER =
  process.env.SHIELDKIT_FRI_WORKER ||
  path.join(ROOT, '.private/cargo-target/release/shieldkit-fri-worker');

export function rustProve({ kind = 'transfer', depth = 4, seed = 1, params = {} } = {}) {
  if (!existsSync(WORKER)) {
    throw new Error(`missing worker ${WORKER}`);
  }
  const req = {
    cmd: 'prove',
    kind,
    depth,
    seed,
    blowup: params.blowup ?? 32,
    queries: params.queries ?? 8,
    grindBits: params.grindBits ?? 8,
    foldStep: params.foldStep ?? 3,
    maskDeg: params.maskDeg ?? 64,
    deep: true,
    ...(params.eligibility ? { eligibility: params.eligibility } : {}),
  };
  const r = spawnSync(WORKER, [], {
    cwd: ROOT,
    input: JSON.stringify(req) + '\n',
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) {
    throw new Error(`rust prove failed: ${r.stderr || r.stdout}`);
  }
  return JSON.parse(r.stdout.trim());
}

/**
 * @returns {{ ok: boolean, rust, assembly, statementMatch: boolean, sizesOk: boolean, vmOk: boolean }}
 */
export function proveAndAssemble({
  kind = 'transfer',
  depth = 4,
  seed = 1,
  blowup = 32,
  nq = 8,
  grind = 8,
  foldStep = 3,
  outDir = path.join(ROOT, 'evidence/settlement-prod'),
} = {}) {
  mkdirSync(outDir, { recursive: true });
  const rust = rustProve({
    kind,
    depth,
    seed,
    params: { blowup, queries: nq, grindBits: grind, foldStep },
  });
  const outPath = path.join(outDir, `assemble-${kind}-d${depth}-b${blowup}-live.json`);
  const assembly = assembleProductionSettlement({
    kind,
    depth,
    nq,
    blowup,
    grind,
    foldStep,
    seed,
    outPath,
  });

  // Statement match (u64 may be string in assembly)
  const rs = rust.statement || {};
  const as_ = assembly.statement || {};
  const norm = (v) => String(v);
  const statementMatch =
    norm(rs.root) === norm(as_.root) &&
    norm(rs.nf) === norm(as_.nf) &&
    norm(rs.depth ?? depth) === norm(as_.depth) &&
    (rs.kind || kind) === (as_.kind || kind);

  const vmOk = assembly.vm?.allAccept === true && assembly.forge?.omit_final?.rejectOk !== false;
  const sizesOk =
    (assembly.vm?.txBytes ?? Infinity) <= MAX_TX_BYTES &&
    (assembly.vm?.maxUnlockBytes ?? Infinity) <= MAX_UNLOCK_BYTES;

  const result = {
    ok:
      rust.verifyOk === true &&
      rust.usesPython === false &&
      assembly.productionVerifiers === true &&
      assembly.placeholder === false &&
      statementMatch &&
      vmOk &&
      sizesOk,
    rust: {
      verifyOk: rust.verifyOk,
      usesPython: rust.usesPython,
      proveSeconds: rust.proveSeconds,
      peakRssBytes: rust.peakRssBytes,
      statement: rust.statement,
      proofBlobSha256: rust.proofBlobSha256,
    },
    assembly: {
      productionVerifiers: assembly.productionVerifiers,
      placeholder: assembly.placeholder,
      nInputs: assembly.nInputs || assembly.roles?.length,
      roles: assembly.roles,
      txBytes: assembly.vm?.txBytes,
      maxUnlockBytes: assembly.vm?.maxUnlockBytes,
      allAccept: assembly.vm?.allAccept,
      forge: assembly.forge,
      vendorPin: assembly.vendorPin,
      statement: assembly.statement,
    },
    statementMatch,
    sizesOk,
    vmOk,
  };

  writeFileSync(
    path.join(outDir, `prove-and-assemble-${kind}.json`),
    JSON.stringify(result, null, 2) + '\n',
  );
  return result;
}

// CLI
if (process.argv[1] && process.argv[1].endsWith('prove_and_assemble.mjs')) {
  const kind = process.argv[2] || 'transfer';
  const depth = Number(process.env.SETTLEMENT_DEPTH || 4);
  const blowup = Number(process.env.SETTLEMENT_BLOWUP || 32);
  const r = proveAndAssemble({ kind, depth, blowup });
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.ok ? 0 : 1);
}
