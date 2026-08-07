/**
 * Product bridge: materialize FRI unlock packs via shieldkit-fri-worker (Rust).
 *
 * Usage:
 *   node packages/settlement/assemble_rust.mjs fri-terms --proof path.json
 *   node packages/settlement/assemble_rust.mjs assemble-unlocks --proof path.json --out out.json
 *
 * Redeems stay profile-fixed (load from green assembly). Unlocks come from proof dump.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const DEFAULT_WORKER = path.join(
  ROOT,
  '.private/cargo-target/release/shieldkit-fri-worker',
);

export function workerBin() {
  return process.env.SHIELDKIT_FRI_WORKER || process.env.VC_FRI_WORKER || DEFAULT_WORKER;
}

export function callFriWorker(req, { timeoutMs = 120_000 } = {}) {
  const bin = workerBin();
  if (!existsSync(bin)) {
    throw new Error(
      `shieldkit-fri-worker missing at ${bin}; run: cargo build -p shieldkit-fri-worker --release`,
    );
  }
  const r = spawnSync(bin, [], {
    input: JSON.stringify(req) + '\n',
    encoding: 'utf8',
    cwd: ROOT,
    timeout: timeoutMs,
    maxBuffer: 256 * 1024 * 1024,
  });
  const lines = (r.stdout || '')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('{'));
  if (!lines.length) {
    throw new Error(
      `fri-worker no JSON status=${r.status} stderr=${(r.stderr || '').slice(0, 800)}`,
    );
  }
  return JSON.parse(lines[lines.length - 1]);
}

export function friTermsFromProof(proofPath) {
  return callFriWorker({ cmd: 'fri-terms', proofPath });
}

export function assembleUnlocksFromProof(proofPath, { out, aggfriPad = 120, redeemsPath } = {}) {
  const req = {
    cmd: 'assemble-unlocks',
    proofPath,
    aggfriPad,
  };
  if (out) req.out = out;
  if (redeemsPath) req.redeemsPath = redeemsPath;
  return callFriWorker(req, { timeoutMs: 300_000 });
}

/**
 * Build redeems JSON for stitch from a materialized assembly artifact.
 */
export function redeemsJsonFromAssembly(assemblyPath, outPath) {
  const raw = JSON.parse(readFileSync(assemblyPath, 'utf8'));
  const roles = raw.roleHex || [];
  if (!roles.length) throw new Error('assembly missing roleHex');
  const redeems = roles.map((r) => ({
    role: r.role,
    index: r.index ?? 0,
    redeem_bytecode_hex: r.redeemBytecodeHex,
    unlock_bytecode_hex: r.unlockBytecodeHex || '',
  }));
  if (outPath) {
    mkdirSync(path.dirname(outPath), { recursive: true });
    writeFileSync(outPath, JSON.stringify(redeems, null, 2) + '\n');
  }
  return redeems;
}

// CLI
if (process.argv[1] && process.argv[1].endsWith('assemble_rust.mjs')) {
  const [cmd, ...rest] = process.argv.slice(2);
  const args = Object.fromEntries(
    rest
      .map((a, i, arr) => (a.startsWith('--') ? [a.slice(2), arr[i + 1]] : null))
      .filter(Boolean),
  );
  try {
    if (cmd === 'fri-terms') {
      const r = friTermsFromProof(args.proof);
      console.log(JSON.stringify({ ok: r.ok, nQueries: r.nQueries, wallSeconds: r.wallSeconds }, null, 2));
      process.exit(r.ok ? 0 : 1);
    }
    if (cmd === 'assemble-unlocks') {
      const r = assembleUnlocksFromProof(args.proof, {
        out: args.out,
        aggfriPad: Number(args.pad || 120),
        redeemsPath: args.redeems,
      });
      console.log(
        JSON.stringify(
          {
            ok: r.ok !== false,
            wallSeconds: r.wall_seconds || r.wallSeconds,
            nQueries: r.n_queries || r.nQueries,
            out: args.out || null,
          },
          null,
          2,
        ),
      );
      process.exit(r.ok === false ? 1 : 0);
    }
    console.error('usage: assemble_rust.mjs fri-terms --proof P.json | assemble-unlocks --proof P.json [--out O] [--redeems R]');
    process.exit(2);
  } catch (e) {
    console.error(String(e.message || e));
    process.exit(1);
  }
}
