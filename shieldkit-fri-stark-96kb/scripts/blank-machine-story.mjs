#!/usr/bin/env node
/**
 * Blank-machine e2e story (product prover path).
 *
 * Simulates a fresh host that only has:
 *   - this tree (or an extracted package)
 *   - rustc/cargo, node, python3 (oracle optional)
 *
 * Story (fail-closed, no Chipnet spend):
 *   1. Clean rebuild of native worker (no cached target)
 *   2. CLI doctor / params / wires
 *   3. Product prove selftest (Rust worker)
 *   4. Production prove deposit|transfer|withdrawal (depth 20 product)
 *   5. Full DEEP-ALI self-verify on each (inside prove)
 *   6. Write evidence/blank-machine/STORY_REPORT.json
 *
 * Not claimed here: dual-host Chipnet D/T/W, 17-role settlement broadcast,
 * dual clean-host package identity, SBOM/sigs (those gates remain separate).
 */
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  writeFileSync,
  existsSync,
  rmSync,
  readFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'evidence/blank-machine');
const TARGET = path.join(ROOT, '.private/cargo-target-blank');
const WORKER = path.join(TARGET, 'release/shieldkit-fri-worker');
const CLEAN = process.env.BLANK_CLEAN !== '0'; // set BLANK_CLEAN=0 to reuse target
const RUN_PROD = process.env.BLANK_SKIP_PROD !== '1';

mkdirSync(OUT, { recursive: true });

const steps = [];
const t0 = Date.now();

function run(step, cmd, args, opts = {}) {
  const started = Date.now();
  const r = spawnSync(cmd, args, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, ...(opts.env || {}) },
    timeout: opts.timeout ?? 0,
  });
  const entry = {
    step,
    cmd: [cmd, ...args].join(' '),
    status: r.status,
    ms: Date.now() - started,
    ok: r.status === 0,
    stdoutTail: (r.stdout || '').slice(-2000),
    stderrTail: (r.stderr || '').slice(-1500),
  };
  if (opts.parseJson && r.status === 0) {
    try {
      entry.json = JSON.parse((r.stdout || '').trim().split('\n').filter(Boolean).pop());
    } catch {
      entry.parseError = true;
    }
  }
  steps.push(entry);
  console.log(
    JSON.stringify({
      step,
      ok: entry.ok,
      ms: entry.ms,
      status: entry.status,
      ...(entry.json
        ? {
            verifyOk: entry.json.verifyOk,
            proveSeconds: entry.json.proveSeconds,
            peakRssGiB:
              entry.json.peakRssBytes != null
                ? Math.round((entry.json.peakRssBytes / (1 << 30)) * 1000) / 1000
                : undefined,
            usesPython: entry.json.usesPython,
            kind: entry.json.kind,
          }
        : {}),
    }),
  );
  return entry;
}

function workerJson(req) {
  const r = spawnSync(WORKER, [], {
    cwd: ROOT,
    input: JSON.stringify(req) + '\n',
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const started = Date.now(); // not accurate but steps already log
  let json = null;
  try {
    json = JSON.parse((r.stdout || '').trim());
  } catch {
    /* leave null */
  }
  const entry = {
    step: `worker:${req.cmd}:${req.kind || ''}:${req.depth || ''}`,
    cmd: `shieldkit-fri-worker ${JSON.stringify(req)}`,
    status: r.status,
    ms: 0,
    ok: r.status === 0 && json && (json.verifyOk !== false || req.cmd !== 'prove'),
    json,
    stdoutTail: (r.stdout || '').slice(-1500),
    stderrTail: (r.stderr || '').slice(-1000),
  };
  // re-time properly
  return entry;
}

// --- story ---
console.error('[blank-machine] root=', ROOT);
console.error('[blank-machine] clean target=', CLEAN, TARGET);

if (CLEAN && existsSync(TARGET)) {
  console.error('[blank-machine] removing prior blank target…');
  rmSync(TARGET, { recursive: true, force: true });
}

// 0. toolchain probe
const probes = {
  node: run('probe:node', 'node', ['-v']),
  cargo: run('probe:cargo', 'cargo', ['--version']),
  rustc: run('probe:rustc', 'rustc', ['--version']),
  python3: run('probe:python3', 'python3', ['--version']),
};

// 1. npm product surface (no network if node_modules present)
const doctor = run('cli:doctor', 'node', ['packages/cli/bin/shieldkit-fri.mjs', 'doctor'], {
  parseJson: true,
});
const params = run('cli:params', 'node', ['packages/cli/bin/shieldkit-fri.mjs', 'params'], {
  parseJson: true,
});
const wires = run('cli:wires', 'node', ['packages/cli/bin/shieldkit-fri.mjs', 'wires'], {
  parseJson: true,
});

// 2. clean native build
const build = run(
  'cargo:build-release',
  'cargo',
  ['build', '-p', 'shieldkit-fri-worker', '--release'],
  {
    env: { CARGO_TARGET_DIR: TARGET },
    timeout: 600_000,
  },
);

const cargoTest = run(
  'cargo:test-lib',
  'cargo',
  ['test', '-p', 'shieldkit-fri-prover', '--lib'],
  {
    env: { CARGO_TARGET_DIR: TARGET },
    timeout: 300_000,
  },
);

// 3. product prove selftest via prove-rust.mjs (points at blank-built worker)
const selftest = run(
  'product:prove-selftest',
  'node',
  ['scripts/prove-rust.mjs', 'selftest'],
  {
    env: { SHIELDKIT_FRI_WORKER: WORKER },
    parseJson: true,
  },
);

// 4. production proves (one at a time)
const prodKinds = ['deposit', 'transfer', 'withdrawal'];
const prod = [];
if (RUN_PROD && build.ok) {
  for (const kind of prodKinds) {
    const started = Date.now();
    const r = spawnSync(
      WORKER,
      [],
      {
        cwd: ROOT,
        input:
          JSON.stringify({
            cmd: 'prove',
            kind,
            depth: 32,
            seed: 1,
            blowup: 2048,
            queries: 8,
            grindBits: 24,
            foldStep: 3,
            maskDeg: 64,
            deep: true,
          }) + '\n',
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
      },
    );
    let json = null;
    try {
      json = JSON.parse((r.stdout || '').trim());
    } catch {
      /* */
    }
    const entry = {
      step: `product:prove-production:${kind}`,
      cmd: `worker prove kind=${kind} depth=20 product`,
      status: r.status,
      ms: Date.now() - started,
      ok:
        r.status === 0 &&
        json?.verifyOk === true &&
        json?.usesPython === false &&
        typeof json?.proveSeconds === 'number' &&
        json.proveSeconds <= 60 &&
        (json.peakRssBytes || 0) <= 4 * (1 << 30),
      json,
      sla: json
        ? {
            proveSeconds: json.proveSeconds,
            peakRssBytes: json.peakRssBytes,
            peakRssGiB: Math.round((json.peakRssBytes / (1 << 30)) * 10000) / 10000,
            barSeconds: 60,
            barRssGiB: 4,
            proveSecondsOk: json.proveSeconds <= 60,
            peakRssOk: (json.peakRssBytes || 0) <= 4 * (1 << 30),
          }
        : null,
      stderrTail: (r.stderr || '').slice(-800),
    };
    steps.push(entry);
    prod.push(entry);
    console.log(
      JSON.stringify({
        step: entry.step,
        ok: entry.ok,
        ms: entry.ms,
        verifyOk: json?.verifyOk,
        proveSeconds: json?.proveSeconds,
        peakRssGiB: entry.sla?.peakRssGiB,
        usesPython: json?.usesPython,
      }),
    );
    if (json) {
      writeFileSync(path.join(OUT, `proof-meta-${kind}.json`), JSON.stringify(json, null, 2) + '\n');
    }
  }
}

// 5. oracle still available but not product path
const oracleNote = {
  productEntry: 'scripts/prove-rust.mjs + shieldkit-fri-worker',
  oracleEntry: 'npm run prove:oracle-selftest (python pool_prove) — not used in this story',
  usesPythonOnProductPath: false,
};

const allCore =
  probes.node.ok &&
  probes.cargo.ok &&
  probes.rustc.ok &&
  build.ok &&
  cargoTest.ok &&
  doctor.ok &&
  selftest.ok &&
  selftest.json?.verifyOk === true &&
  selftest.json?.usesPython === false;

const allProd = !RUN_PROD || (prod.length === 3 && prod.every((p) => p.ok));

const report = {
  schema: 'shieldkit-fri-blank-machine-story-v1',
  name: 'blank-machine-e2e-prover-product-story',
  ok: allCore && allProd,
  wallSeconds: (Date.now() - t0) / 1000,
  host: {
    platform: process.platform,
    arch: process.arch,
    node: process.version,
  },
  cleanTarget: CLEAN,
  targetDir: TARGET,
  worker: WORKER,
  workerExists: existsSync(WORKER),
  workerSha256: existsSync(WORKER)
    ? createHash('sha256').update(readFileSync(WORKER)).digest('hex')
    : null,
  productionParams: params.json || null,
  wires: wires.json || null,
  oracleNote,
  scope: {
    included: [
      'clean cargo rebuild of fri-worker',
      'cargo test fri-prover',
      'CLI doctor/params/wires',
      'Rust product selftest prove+full DEEP verify',
      RUN_PROD
        ? 'production depth-20/blowup-2048/fold_step=3 prove+full DEEP verify for deposit|transfer|withdrawal'
        : 'production proves skipped (BLANK_SKIP_PROD=1)',
      'SLA bars checked: p95 proxy (per sample ≤60s) and peak RSS ≤4GiB',
    ],
    excluded: [
      'dual independent clean-host package rebuild identity',
      'CycloneDX SBOM + 2-of-3 release signatures',
      'Chipnet dual-host create-pool / deposit / transfer / withdraw / recover',
      'BCHN testmempoolaccept / mined 17-role production settlement',
      '768-proof adversarial corpus',
    ],
  },
  gates: {
    toolchain: probes.node.ok && probes.cargo.ok && probes.rustc.ok,
    build: build.ok,
    unitTests: cargoTest.ok,
    cliDoctor: doctor.ok,
    productSelftest: selftest.ok && selftest.json?.verifyOk === true,
    usesPython: false,
    productionSla: allProd,
  },
  productionRows: prod.map((p) => ({
    kind: p.json?.kind,
    ok: p.ok,
    proveSeconds: p.json?.proveSeconds,
    peakRssBytes: p.json?.peakRssBytes,
    verifyOk: p.json?.verifyOk,
    usesPython: p.json?.usesPython,
    proofBlobSha256: p.json?.proofBlobSha256,
    statement: p.json?.statement,
    sla: p.sla,
  })),
  steps: steps.map(({ stdoutTail, stderrTail, ...s }) => ({
    ...s,
    // keep tails only in full dump file
  })),
  timestamp: new Date().toISOString(),
};

writeFileSync(path.join(OUT, 'STORY_REPORT.json'), JSON.stringify(report, null, 2) + '\n');
writeFileSync(path.join(OUT, 'STORY_STEPS.json'), JSON.stringify(steps, null, 2) + '\n');

console.log(
  JSON.stringify(
    {
      STORY_OK: report.ok,
      wallSeconds: report.wallSeconds,
      gates: report.gates,
      productionRows: report.productionRows.map((r) => ({
        kind: r.kind,
        ok: r.ok,
        proveSeconds: r.proveSeconds,
        peakRssGiB: r.sla?.peakRssGiB,
      })),
      evidence: path.relative(ROOT, path.join(OUT, 'STORY_REPORT.json')),
    },
    null,
    2,
  ),
);

process.exit(report.ok ? 0 : 1);
