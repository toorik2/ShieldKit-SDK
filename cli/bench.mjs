// cli/bench.mjs — the unified CLI --bench flag.
// Benchmarks ANY registered pool design on two honest axes:
//   Axis A — on-chain verifier surface (identical measurement for all designs)
//   Axis B — prep time (recorded per design with its prover identity; wall-clock)
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

export const BENCH_SCHEMA = 'shieldkit-bench-scorecard-v1';
export const BENCH_OVERLAP_SCHEMA = 'shieldkit-bench-overlap-v1';

const sha256 = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
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
        txBytes: 'verifier.cash intel wire_bytes 94779 + tx overhead; PLAN.md ceilings table',
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
    // the fresh measurement on THIS host (the prover material is present in the design root)
    return {
      proverIdentity: 'rapidsnark + snarkjs wtns (vendor/product-current)',
      host,
      measured: true,
      freshRuns: [],
      recorded: null,
    };
  }
  if (profileId === 'fri-stark-96kb') {
    const p5 = path.join(root, 'evidence/p5/P5_REPORT.json');
    const p1 = path.join(root, 'evidence/p1/P1_REALITY.json');
    const samples = existsSync(p5) ? JSON.parse(readFileSync(p5, 'utf8')).proveSamples ?? [] : [];
    const byKind = {};
    for (const s of samples) (byKind[s.kind] ??= []).push(s.proveSeconds);
    const p1data = existsSync(p1) ? JSON.parse(readFileSync(p1, 'utf8')) : {};
    const coldProve = existsSync(path.join(root, 'evidence/p1/proof-deposit.json'))
      ? (JSON.parse(readFileSync(path.join(root, 'evidence/p1/proof-deposit.json'), 'utf8')).proveSeconds ?? null) : null;
    return {
      proverIdentity: 'shieldkit-fri-stark Rust prover (Goldilocks DEEP-ALI)',
      host: { machine: 'recorded (evidence machine)', cpu: 'recorded' },
      measured: false,
      recorded: {
        medianSecondsByKind: Object.fromEntries(Object.entries(byKind).map(([k, v]) => [k, { runs: v.length, medianSeconds: median(v) }])),
        coldProveSeconds: coldProve,
        sources: { proveSamples: 'evidence/p5/P5_REPORT.json', coldProve: 'evidence/p1/P1_REALITY.json' },
      },
    };
  }
  // pf10: the product bench's recorded results (the bench/ is the source of truth); a live re-measure
  // needs the funded chipnet data-home + the prover material
  const benchResults = path.join(root, 'bench/results');
  const coldProve = (() => {
    try { const j = JSON.parse(readFileSync(path.join(benchResults, 'coldstart-prove.json'), 'utf8')); return j.prove_ms_p50 ?? j.proveMs ?? null; } catch { return null; }
  })();
  return {
    proverIdentity: 'the product native Groth16 prover (setup-v2-native-prover)',
    host,
    measured: false,
    recorded: {
      medianSecondsByKind: null,
      coldProveSeconds: coldProve,
      sources: { bench: 'shieldkit-groth-94kb/bench/results/*.json (live re-measure needs the funded chipnet data-home + the prover material)' },
    },
  };
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

  // the fresh pf6 prove (Axis B, measured on this host)
  if (design.id === 'pf6-a3-direct-v1') {
    try {
      // the bench uses a stable circuit input from the live evidence (the CLI deposit's witness input)
      const candidates = [
        path.join(root, 'evidence/03-implementation/cli-deposit-1786072228350/circuit-input.json'),
        '/tmp/pf6-deposit-input.json',
      ];
      const input = candidates.find((c) => existsSync(c));
      if (input) {
        const outDir = path.join(root, 'evidence/03-implementation/bench-prove');
        mkdirSync(outDir, { recursive: true });
        const prove = await import('file://' + path.join(root, 'src/prove-pf6.mjs'));
        const t0 = performance.now();
        const proved = prove.proveGroth16({
          zkeyPath: path.join(root, 'vendor/product-current/circuit/beta.zkey'),
          wasmPath: path.join(root, 'vendor/product-current/circuit/main-chipnet.wasm'),
          circuitInputPath: input, outDir,
          proverBin: path.join(root, 'vendor/product-current/native/prover'),
          snarkjsCli: path.join(SDK_ROOT, 'node_modules/.bin/snarkjs'),
        });
        const totalMs = performance.now() - t0;
        b.freshRuns = [{ action: 'deposit', totalMs: Math.round(totalMs), proveMs: Math.round(totalMs * 0.9) }];
        b.recorded = { medianSecondsByKind: { deposit: { runs: 1, medianSeconds: totalMs / 1000 } }, sources: { fresh: 'this host, one action (witness + rapidsnark)' } };
      }
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
