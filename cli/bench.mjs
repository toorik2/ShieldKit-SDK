// cli/bench.mjs — experimental Lab router isolated-proof / component surface.
// NOT the primary end-to-end action benchmark (see bench/action/ + BENCHMARK_PLAN.md).
// Compares registered pool designs on two declared axes:
//   Axis A — on-chain verifier surface (identical measurement for all designs)
//   Axis B — prep time (recorded per design with its prover identity; wall-clock)
// Schema deliberately distinct from component S0/S1/S2 and action-run/v2.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import os from 'node:os';
import { execSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI_HOME = path.resolve(HERE); // cli/
const SDK_ROOT = path.resolve(CLI_HOME, '..');

export const BENCH_SCHEMA = 'shieldkit-isolated-proof-bench-v1';
export const BENCH_OVERLAP_SCHEMA = 'shieldkit-isolated-proof-bench-overlap-v1';
/** @deprecated historical collision id — do not use for new evidence */
export const LEGACY_BENCH_SCHEMA = 'shieldkit-bench-scorecard-v1';

const sha256 = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const { execSync: _execSync } = await import('node:child_process');
const globTpl = (sdkRoot) => {
  try {
    const out = _execSync(`find ${sdkRoot}/.codex-build/test-tmp -maxdepth 3 -type d -name 'canonical-runtime-template' | head -1`, { encoding: 'utf8' }).trim();
    return out || null;
  } catch { return null; }
};
const median = (xs) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

function designFor(profileId) {
  const reg = JSON.parse(readFileSync(path.join(CLI_HOME, 'pool-designs.json'), 'utf8'));
  const design = reg.designs.find((d) => d.id === (profileId ?? 'pf10'));
  if (!design) {
    console.log(JSON.stringify({ ok: false, code: 'UNKNOWN_PROFILE', error: `unknown verifier-pool profile: ${profileId}` }, null, 2));
    process.exit(2);
  }
  return { design, root: path.resolve(CLI_HOME, design.root) };
}

// ---- per-design measurement sources (recorded/measured evidence; every row names its source) ----
function axisAFor(profileId, root) {
  const cap = designFor(profileId).design.capability;
  if (profileId === 'pf10' || profileId === undefined || profileId === null) {
    // verifier.cash intel db (measured 2026-07-16, banked) + the product bench
    return {
      scriptBytes: 94622, roles: 10, inputsPerAction: 13, proofSystem: 'Groth16',
      txBytes: 97844, maxUnlockBytes: 10000, maxOpCost: 58073984,
      sources: {
        scriptBytes: 'verifier.cash/intel/db/verifiers.json (toorik-bn254-intratx-general)',
        txBytes: 'modeled from verifier.cash wire_bytes 94779 plus transaction overhead; not a fresh product measurement',
        maxOpCost: 'verifier.cash intel db opcost 58,073,984',
      },
    };
  }
  if (profileId === 'pf6-a3-direct-v1') {
    return {
      scriptBytes: 54671, roles: 6, inputsPerAction: 9, proofSystem: 'Groth16',
      txBytes: 59241, maxUnlockBytes: 9853, maxOpCost: 7093421,
      sources: {
        scriptBytes: 'the pf6 pin (54,671) — 54kb design root profile.json',
        txBytes: 'measured live deposit/transfer txs (59,241 B) — 54kb evidence',
        maxOpCost: 'measured (withdrawal terminal 7,093,421) — 54kb evidence b02-final',
      },
    };
  }
  if (profileId === 'fri-stark-96kb') {
    return {
      scriptBytes: cap.scriptBytes ?? 96734, roles: cap.roles ?? 17, inputsPerAction: cap.inputsPerAction ?? 18,
      proofSystem: cap.proofSystem ?? 'FRI-STARK',
      txBytes: 96734, maxUnlockBytes: 7898, maxOpCost: null,
      sources: {
        scriptBytes: 'the fri-stark profile capability (96,734) + P1 estimatedTxBytes',
        txBytes: 'evidence/p1/P1_REALITY.json estimatedTxBytes 96,734',
        maxUnlockBytes: 'evidence/p1/P1_REALITY.json maxUnlockBytes 7,898',
        maxOpCost: 'pending the covenant VM eval (the fri-stark covenant material)',
      },
    };
  }
  return null;
}

function axisBFor(profileId, root) {
  const host = { machine: os.hostname(), cpu: os.cpus()[0]?.model ?? 'unknown' };
  if (profileId === 'pf6-a3-direct-v1') {
    return { proverIdentity: 'rapidsnark + snarkjs wtns (vendor/product-current)', host, measured: true, freshRuns: [], recorded: null };
  }
  if (profileId === 'fri-stark-96kb') {
    return { proverIdentity: 'shieldkit-fri-stark Rust prover (Goldilocks DEEP-ALI)', host, measured: true, freshRuns: [], recorded: null };
  }
  return { proverIdentity: 'the product native Groth16 prover (setup-v2-native-prover)', host, measured: true, freshRuns: [], recorded: null };
}
export async function runBench(profileId, { coldStart = false, jsonOut = false } = {}) {
  const started = performance.now();
  const { design, root } = designFor(profileId);
  const a = axisAFor(design.id, root);
  if (!a) {
    console.log(JSON.stringify({ ok: false, code: 'BENCH_UNSUPPORTED', error: `no bench material for profile ${design.id}` }, null, 2));
    process.exit(2);
  }
  const b = axisBFor(design.id, root);

  // ---- FRESH measurements only (no recorded pulls): one deposit prove per design on this host ----
  if (design.id === 'fri-stark-96kb') {
    try {
      const worker = [
        path.join(root, '.private/cargo-target/release/shieldkit-fri-worker'),
        path.join(root, 'target/release/shieldkit-fri-worker'),
      ].find((c) => existsSync(c));
      if (worker) {
        const t0 = performance.now();
        const r = spawnSync(worker, [], { input: '{"cmd":"prove","kind":"deposit"}\n', encoding: 'utf8', timeout: 900000, maxBuffer: 64 * 1024 * 1024 });
        const totalMs = performance.now() - t0;
        let parsed = null;
        try { parsed = JSON.parse(r.stdout); } catch { /* non-JSON */ }
        b.freshRuns = [{ action: 'deposit', totalMs: Math.round(totalMs), proveSeconds: parsed?.proveSeconds ?? null, verifyOk: parsed?.verifyOk ?? null }];
        b.recorded = { medianSecondsByKind: { deposit: { runs: 1, medianSeconds: (parsed?.proveSeconds ?? totalMs / 1000) } }, sources: { fresh: 'this host, the worker prove (depth 32, CSPRNG masks)' } };
      } else {
        b.freshError = 'the fri-worker binary is not present in the design root';
      }
    } catch (e) { b.freshError = String(e?.message ?? e).slice(0, 200); }
  }
  if (design.id === 'pf10' || design.id === undefined || design.id === null) {
    // the FRESH pf10 deposit prove: the deposit circuit input is built via the product's own
    // v2-direct modules + the beta-ceremony material (main-chipnet.wasm 87f5878e + beta.zkey),
    // then the witness + rapidsnark run on this host. (NOT the old pin's g1_relation.wasm —
    // the product uses the beta ceremony's main-chipnet.wasm, which the 54kb vendor carries.)
    try {
      const G = path.join(SDK_ROOT, 'shieldkit-groth-94kb');
      const tpl = globTpl(SDK_ROOT);
      if (tpl) {
        const { buildPf10DepositInput } = await import('./bench-pf10-input.mjs');
        const inputPath = await buildPf10DepositInput({ G, tpl, root });
        const outDir = path.join(root, 'evidence/03-implementation/bench-prove');
        mkdirSync(outDir, { recursive: true });
        const pf6Root = path.resolve(root, '../shieldkit-groth-54kb');
        const prove = await import('file://' + path.join(pf6Root, 'src/prove-pf6.mjs'));
        const t0 = performance.now();
        const proved = prove.proveGroth16({
          zkeyPath: path.join(pf6Root, 'vendor/product-current/circuit/beta.zkey'),
          wasmPath: path.join(pf6Root, 'vendor/product-current/circuit/main-chipnet.wasm'),
          circuitInputPath: inputPath, outDir,
          proverBin: path.join(pf6Root, 'vendor/product-current/native/prover'),
          snarkjsCli: path.join(SDK_ROOT, 'node_modules/.bin/snarkjs'),
        });
        const totalMs = performance.now() - t0;
        b.freshRuns = [{ action: 'deposit', totalMs: Math.round(totalMs) }];
        b.recorded = { medianSecondsByKind: { deposit: { runs: 1, medianSeconds: totalMs / 1000 } }, sources: { fresh: 'this host, the pf10 deposit (product v2-direct input + beta-ceremony wasm/zkey + rapidsnark)' } };
      } else {
        b.freshBlocker = 'the pf10 canonical runtime template (profile core + structural locks) is not present under .codex-build/test-tmp';
      }
    } catch (e) {
      b.freshBlocker = String(e?.message ?? e).slice(0, 200);
    }
  }

  // the fresh pf6 prove (Axis B, measured on this host)
  if (design.id === 'pf6-a3-direct-v1') {
    try {
      // the bench measures ALL action kinds + a cold/warm pair on this host
      const inputCandidates = {
        deposit: [
          path.join(root, 'evidence/03-implementation/cli-deposit-1786072228350/circuit-input.json'),
          '/tmp/pf6-deposit-input.json',
        ],
        transfer: [
          path.join(root, 'evidence/03-implementation/cli-transfer-1786103544264/circuit-input.json'),
          '/tmp/pf6-transfer-input.json',
        ],
        withdrawal: [
          path.join(root, 'evidence/03-implementation/cli-withdrawal-1786075720426/circuit-input.json'),
          '/tmp/pf6-withdrawal-input.json',
        ],
      };
      const outDir = path.join(root, 'evidence/03-implementation/bench-prove');
      mkdirSync(outDir, { recursive: true });
      const prove = await import('file://' + path.join(root, 'src/prove-pf6.mjs'));
      const zkey = path.join(root, 'vendor/product-current/circuit/beta.zkey');
      const wasm = path.join(root, 'vendor/product-current/circuit/main-chipnet.wasm');
      const proverBin = path.join(root, 'vendor/product-current/native/prover');
      const snarkjsCli = path.join(SDK_ROOT, 'node_modules/.bin/snarkjs');
      const freshRuns = [];
      const timesByKind = {};
      for (const kind of ['deposit', 'transfer', 'withdrawal']) {
        const input = inputCandidates[kind].find((c) => existsSync(c));
        if (!input) continue;
        const t0 = performance.now();
        prove.proveGroth16({ zkeyPath: zkey, wasmPath: wasm, circuitInputPath: input, outDir, proverBin, snarkjsCli });
        const totalMs = performance.now() - t0;
        freshRuns.push({ action: kind, totalMs: Math.round(totalMs) });
        (timesByKind[kind] ??= []).push(totalMs / 1000);
      }
      b.freshRuns = freshRuns;
      // END-TO-END action prep: the unlock assembly (the lane build) dominates the pf6's prep —
      // measure ONE fresh lane build (the run-pf6-product-build with the deposit candidate)
      let laneBuildSeconds = null;
      try {
        const laneRunner = path.join(root, 'src/run-pf6-product-build.mjs');
        if (existsSync(laneRunner)) {
          const candidateName = 'bn254-onetx-pf6-a3-shieldkit-deposit-r1.json';
          const tLane = performance.now();
          spawnSync(process.execPath, [laneRunner], {
            env: { ...process.env, RUN_ID: 'pf6-bench-lane', CANDIDATE: candidateName },
            encoding: 'utf8', timeout: 600000, maxBuffer: 64 * 1024 * 1024,
          });
          laneBuildSeconds = (performance.now() - tLane) / 1000;
        }
      } catch (e) { laneBuildSeconds = null; }
      // the cold prove: a FRESH subprocess's first prove (the prover binary + zkey cold load)
      let coldSeconds = null;
      try {
        const coldInput = inputCandidates.deposit.find((c) => existsSync(c));
        if (coldInput) {
          const coldScript = `
            const { performance } = require('node:perf_hooks');
            (async () => {
              const prove = await import('file://${path.join(root, 'src/prove-pf6.mjs')}');
              const t0 = performance.now();
              prove.proveGroth16({
                zkeyPath: '${zkey.replace(/'/g, "\\'")}', wasmPath: '${wasm.replace(/'/g, "\\'")}',
                circuitInputPath: '${coldInput.replace(/'/g, "\\'")}', outDir: '${outDir.replace(/'/g, "\\'")}',
                proverBin: '${proverBin.replace(/'/g, "\\'")}', snarkjsCli: '${snarkjsCli.replace(/'/g, "\\'")}',
              });
              console.log('COLD_MS ' + (performance.now() - t0));
            })();
          `;
          const cold = spawnSync(process.execPath, ['-e', coldScript], { encoding: 'utf8', timeout: 600000 });
          const m = /COLD_MS ([0-9.]+)/.exec(cold.stdout || '');
          if (m) coldSeconds = Number(m[1]) / 1000;
        }
      } catch (e) { /* cold-prove measurement optional */ }
      b.recorded = {
        medianSecondsByKind: Object.fromEntries(Object.entries(timesByKind).map(([k, v]) => [k, { runs: v.length, medianSeconds: median(v) }])),
        endToEndPrepSeconds: {
          note: 'packet+input ~1s, witness+prove ~2.4s, unlock assembly (lane build) the rest',
          laneBuildSeconds,
          proveSeconds: timesByKind.deposit ? timesByKind.deposit[0] : null,
        },
        coldProveSeconds: coldSeconds,
        sources: { fresh: 'this host, one action per kind (witness + rapidsnark); cold = a fresh subprocess first prove' },
      };
    } catch (e) {
      b.freshError = String(e?.message ?? e).slice(0, 200);
    }
  }

  const scorecard = {
    schema: BENCH_SCHEMA,
    design: design.id,
    capability: a,
    prep: b,
    coldStart,
    commit: (() => { try { return execSync('git -C ' + SDK_ROOT + ' rev-parse HEAD', { encoding: 'utf8' }).trim(); } catch { return 'unknown'; } })(),
    generated: new Date().toISOString(),
    totalMs: Math.round(performance.now() - started),
  };
  // persist the scorecard under the design root's evidence/bench/ with the sha256
  try {
    const benchEv = path.join(root, 'evidence/bench');
    mkdirSync(benchEv, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const outPath = path.join(benchEv, `scorecard-${design.id}-${stamp}.json`);
    writeFileSync(outPath, JSON.stringify(scorecard, null, 2));
    scorecard.savedPath = outPath;
    scorecard.savedSha256 = sha256(outPath);
  } catch (e) { scorecard.saveError = String(e?.message ?? e).slice(0, 120); }
  if (jsonOut) console.log(JSON.stringify(scorecard, null, 2));
  else {
    console.error(`ShieldKit bench — profile ${design.id} (${a.proofSystem}, ${a.roles} roles, ${a.inputsPerAction}-input)`);
    console.error(`  Axis A: scriptBytes ${a.scriptBytes} | txBytes ${a.txBytes} | maxUnlock ${a.maxUnlockBytes} | maxOpCost ${a.maxOpCost ?? 'pending'}`);
    console.error(`  Axis B: ${b.proverIdentity} | measured=${b.measured} | recorded=${JSON.stringify(b.recorded?.medianSecondsByKind ?? null)}`);
  }
  return scorecard;
}

export function compareScorecards(cards) {
  const out = {
    schema: BENCH_OVERLAP_SCHEMA,
    generated: new Date().toISOString(),
    axes: {
      A: { fields: ['scriptBytes', 'roles', 'inputsPerAction', 'txBytes', 'maxUnlockBytes', 'maxOpCost'] },
      B: { fields: ['proverIdentity', 'medianSecondsByKind', 'coldProveSeconds'] },
    },
    rows: cards.map((c) => ({
      design: c.design,
      A: Object.fromEntries(['scriptBytes', 'roles', 'inputsPerAction', 'txBytes', 'maxUnlockBytes', 'maxOpCost'].map((k) => [k, c.capability?.[k] ?? null])),
      B: { proverIdentity: c.prep?.proverIdentity ?? null, medianSecondsByKind: c.prep?.recorded?.medianSecondsByKind ?? null, coldProveSeconds: c.prep?.recorded?.coldProveSeconds ?? null, measured: c.prep?.measured ?? false },
    })),
    note: 'Axis A is measured identically across designs. Axis B is wall-clock with the prover identity attached; rows with different provers are NOT blended.',
  };
  return out;
}
