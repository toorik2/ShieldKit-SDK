#!/usr/bin/env node
import { repoPath as vcRepoPath } from '#repo-paths';
// Measure the already-landed fixed-line point*e(z) hoist in the live c7/9xK7
// interior body. This is a source spike: it compiles the current emitted source,
// then compiles de-hoisted variants generated from that same source. It does not
// edit the live pairing artifact.
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  bigIntToVmNumber,
  binToHex,
  encodeDataPush,
  createVirtualMachineBch2026,
  hash256,
  hexToBin,
} from '@bitauth/libauth';

const DEFAULT_PAIRING_DIR =
  '/tmp/claude-1000/-home-toorik-Projects/3d59efdb-4f3d-48d8-bf73-7d0a0d781fb8/scratchpad/fundamental-fix/comp-direct-port/build/chunked/pairing';

const pairingDir = resolve(process.env.FIXLINE_PAIRING_DIR ?? process.env.C7_PAIRING_DIR ?? DEFAULT_PAIRING_DIR);
const optimizerDir = resolve(process.env.FIXLINE_OPTIMIZER_DIR ?? vcRepoPath('tools/singleton-artifact'));
const useOptimizer = process.env.FIXLINE_OPTIMIZE !== '0';
const padNopBytes = Number(process.env.FIXLINE_PAD_NOP ?? 0);
const padPushBytes = Number(process.env.FIXLINE_PAD_PUSH ?? 0);
const windows = (process.env.FIXLINE_WINDOWS ?? '1:8,8:15,57:64')
  .split(',')
  .map((w) => w.trim())
  .filter(Boolean)
  .map((w) => {
    const m = w.match(/^(\d+):(\d+)$/);
    if (!m) throw new Error(`bad FIXLINE_WINDOWS entry "${w}", expected lo:hi`);
    return [Number(m[1]), Number(m[2])];
  });

const req = ['gen_miller_gb3_9k7.mjs', 't3_shared3_9k7.mjs', '_millermath.mjs'];
for (const f of req) {
  if (!existsSync(join(pairingDir, f))) throw new Error(`missing ${join(pairingDir, f)}`);
}

const [{ genChunkGB, inBlobGB, outBlobGB, NW, wdatBytesForChunk, STATE_BYTES }, mm] = await Promise.all([
  import(pathToFileURL(join(pairingDir, 'gen_miller_gb3_9k7.mjs')).href),
  import(pathToFileURL(join(pairingDir, '_millermath.mjs')).href),
]);

const { compileFileBytecode } = mm;
const OP = {
  _0: 0x00,
  _1: 0x51,
  _3: 0x53,
  DROP: 0x75,
  DUP: 0x76,
  NIP: 0x77,
  SPLIT: 0x7f,
  EQUALVERIFY: 0x88,
  HASH256: 0xaa,
  INPUTBYTECODE: 0xca,
  DEFINE: 0x89,
  INVOKE: 0x8a,
};
const LIB_ID = 100n;
const realVm = createVirtualMachineBch2026(false);
const b = (...xs) => Uint8Array.from(xs);
const cat = (...xs) => {
  const out = new Uint8Array(xs.reduce((n, x) => n + x.length, 0));
  let p = 0;
  for (const x of xs) {
    out.set(x, p);
    p += x.length;
  }
  return out;
};
const push = (d) => encodeDataPush(d);
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const accept = (st) => st.error === undefined && st.stack.length === 1 && st.stack[0]?.length === 1 && st.stack[0][0] === 1;
const glueCore = (digest) => cat(
  b(OP._0, OP.INPUTBYTECODE),
  b(OP.DUP, OP.HASH256),
  push(digest),
  b(OP.EQUALVERIFY),
  b(OP._3, OP.SPLIT, OP.NIP),
  pushInt(LIB_ID),
  b(OP.DEFINE),
  pushInt(LIB_ID),
  b(OP.INVOKE),
);
const glue = (digest) => padPushBytes > 0 ? cat(b(OP.DROP), glueCore(digest)) : glueCore(digest);
const nopPad = padNopBytes > 0 ? Uint8Array.from(Array(padNopBytes).fill(0x61)) : new Uint8Array(0);
const pushPad = padPushBytes > 0 ? push(new Uint8Array(padPushBytes)) : new Uint8Array(0);

function gitShort(dir) {
  const r = spawnSync('git', ['-C', dir, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

function gitStatus(dir) {
  const r = spawnSync('git', ['-C', dir, 'status', '--short'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim().split('\n').filter(Boolean) : [];
}

function packageVersion(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8')).version ?? null;
  } catch {
    return null;
  }
}

function makeTempCompilerDir() {
  const root = mkdtempSync(join(tmpdir(), 'fixline-pointex-hoist-'));
  const probeDir = join(root, 'build', 'chunked', 'pairing', 'generated');
  mkdirSync(probeDir, { recursive: true });
  const singleton = resolve(pairingDir, '..', '..', 'singleton');
  symlinkSync(singleton, join(root, 'build', 'singleton'), 'dir');
  return { root, probeDir };
}

function compileSource(src, label) {
  const { root, probeDir } = makeTempCompilerDir();
  try {
    const file = join(probeDir, `${label}.cash`);
    writeFileSync(file, src);
    return {
      redeem: Uint8Array.from([...compileFileBytecode(file)]),
      tempRoot: root,
    };
  } catch (e) {
    rmSync(root, { recursive: true, force: true });
    throw e;
  }
}

function optimizeBody(body, label) {
  if (!useOptimizer) return { body, applied: false, rawBytes: body.length };
  const root = mkdtempSync(join(tmpdir(), 'fixline-pointex-hoist-opt-'));
  try {
    const inHex = join(root, `${label}.in.hex`);
    const optHex = join(root, `${label}.opt.hex`);
    const canHex = join(root, `${label}.canon.hex`);
    writeFileSync(inHex, binToHex(body));
    let r = spawnSync('node', [join(optimizerDir, 'optimize.mjs'), inHex, optHex], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`optimize failed: ${(r.stderr || r.stdout || '').slice(0, 400)}`);
    r = spawnSync('node', [join(optimizerDir, 'minpush_canon.mjs'), optHex, canHex], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`minpush_canon failed: ${(r.stderr || r.stdout || '').slice(0, 400)}`);
    const opt = hexToBin(readFileSync(canHex, 'utf8').trim());
    return { body: opt, applied: true, rawBytes: body.length, optimizedDeltaBytes: opt.length - body.length };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function evaluateBody(body, inBlob) {
  const libUnlock = push(body);
  const digest = hash256(libUnlock);
  const execLock = glue(digest);
  const execUnlock = cat(push(inBlob), nopPad, pushPad);
  const inputs = [
    { lock: b(OP.DROP, OP._1), unlock: libUnlock },
    { lock: execLock, unlock: execUnlock },
  ];
  const state = realVm.evaluate({
    inputIndex: 1,
    sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.lock, valueSatoshis: 1000n })),
    transaction: {
      version: 2,
      inputs: inputs.map((i, k) => ({
        outpointTransactionHash: new Uint8Array(32),
        outpointIndex: k,
        sequenceNumber: 0,
        unlockingBytecode: i.unlock,
      })),
      outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }],
      locktime: 0,
    },
  });
  const metrics = state.metrics ?? {};
  return {
    accepted: accept(state),
    error: state.error ? String(state.error) : null,
    opCost: metrics.operationCost ?? null,
    maxOp: metrics.maximumOperationCost ?? null,
    arithmeticCost: metrics.arithmeticCost ?? null,
    baseCost: (metrics.evaluatedInstructionCount ?? 0) * 100,
    pushedBytes: metrics.stackPushedBytes ?? null,
    hashIters: metrics.hashDigestIterations ?? null,
    instr: metrics.evaluatedInstructionCount ?? null,
    bodyBytes: body.length,
    libUnlockBytes: libUnlock.length,
    execLockBytes: execLock.length,
    execUnlockBytes: execUnlock.length,
    padNopBytes,
    padPushBytes,
  };
}

function replaceOnce(src, needle, replacement, label) {
  const n = src.split(needle).length - 1;
  if (n !== 1) throw new Error(`${label}: expected one match, found ${n}`);
  return src.replace(needle, replacement);
}

function replaceAllAtLeastOne(src, needle, replacement, label) {
  const n = src.split(needle).length - 1;
  if (n < 1) throw new Error(`${label}: expected at least one match, found ${n}`);
  return src.split(needle).join(replacement);
}

const currentFold = `function fold1(int Pm, int pf, int c0a,int c0b,int c1a,int c1b,int c2a,int c2b, int kye0,int kye1,int kxe2,int kxe3, int ex4,int ex5) returns (int) {
    return (pf * ((c2a*kye0 + c2b*kye1 + c1a*kxe2 + c1b*kxe3 + c0a*ex4 + c0b*ex5) % Pm)) % Pm; }`;

const inlineUnhoistedFold = `function fold1(int Pm, int pf, int c0a,int c0b,int c1a,int c1b,int c2a,int c2b, int px,int py, int ex0,int ex1,int ex2,int ex3,int ex4,int ex5) returns (int) {
    return (pf * ((c2a*py*ex0 + c2b*py*ex1 + c1a*px*ex2 + c1b*px*ex3 + c0a*ex4 + c0b*ex5) % Pm)) % Pm; }`;

const lineFzFold = `function fold1(int Pm, int pf, int c0a,int c0b,int c1a,int c1b,int c2a,int c2b, int px,int py, int ex0,int ex1,int ex2,int ex3,int ex4,int ex5) returns (int) {
    int fz = (mulFp(mulFp(c2a, py), ex0) + mulFp(mulFp(c2b, py), ex1) + mulFp(mulFp(c1a, px), ex2) + mulFp(mulFp(c1b, px), ex3) + mulFp(c0a, ex4) + mulFp(c0b, ex5)) % Pm;
    return mulFp(pf, fz); }`;

const precomputeBlock = `        int kn0 = (nAy * ex0) % P; int kn1 = (nAy * ex1) % P; int kn2 = (nAx * ex2) % P; int kn3 = (nAx * ex3) % P;
        int kv0 = (vkxY * ex0) % P; int kv1 = (vkxY * ex1) % P; int kv2 = (vkxX * ex2) % P; int kv3 = (vkxX * ex3) % P;
        int kc0 = (Cy * ex0) % P; int kc1 = (Cy * ex1) % P; int kc2 = (Cx * ex2) % P; int kc3 = (Cx * ex3) % P;`;

function dehoistSource(src, mode) {
  const fold = mode === 'lineFz-faithful' ? lineFzFold : inlineUnhoistedFold;
  let out = replaceOnce(src, currentFold, fold, `${mode}/fold1`);
  out = replaceOnce(out, precomputeBlock, '        // point*e(z) precompute removed by fixline-pointex de-hoist source spike.', `${mode}/precompute`);
  out = replaceOnce(
    out,
    `int kn0,int kn1,int kn2,int kn3, int kv0,int kv1,int kv2,int kv3, int kc0,int kc1,int kc2,int kc3, int Bxa,int Bxb,int Bya,int Byb,`,
    `int nAx,int nAy, int vkxX,int vkxY, int Cx,int Cy, int ex0,int ex1,int ex2,int ex3, int Bxa,int Bxb,int Bya,int Byb,`,
    `${mode}/stepU signature`,
  );
  out = replaceAllAtLeastOne(
    out,
    `kn0,kn1,kn2,kn3, kv0,kv1,kv2,kv3, kc0,kc1,kc2,kc3, Bxa,Bxb,Bya,Byb,`,
    `nAx,nAy, vkxX,vkxY, Cx,Cy, ex0,ex1,ex2,ex3, Bxa,Bxb,Bya,Byb,`,
    `${mode}/stepU call`,
  );
  const replacements = [
    [`fold1(Pm, pf, a0,a1,a2,a3,a4,a5, kn0,kn1,kn2,kn3, ex4,ex5)`, `fold1(Pm, pf, a0,a1,a2,a3,a4,a5, nAx,nAy, ex0,ex1,ex2,ex3, ex4,ex5)`],
    [`fold1(Pm, pf, b0,b1,b2,b3,b4,b5, kv0,kv1,kv2,kv3, ex4,ex5)`, `fold1(Pm, pf, b0,b1,b2,b3,b4,b5, vkxX,vkxY, ex0,ex1,ex2,ex3, ex4,ex5)`],
    [`fold1(Pm, pf, uo0,uo1,uo2,uo3,uo4,uo5, kc0,kc1,kc2,kc3, ex4,ex5)`, `fold1(Pm, pf, uo0,uo1,uo2,uo3,uo4,uo5, Cx,Cy, ex0,ex1,ex2,ex3, ex4,ex5)`],
    [`fold1(Pm, pf, aa0,aa1,aa2,aa3,aa4,aa5, kn0,kn1,kn2,kn3, ex4,ex5)`, `fold1(Pm, pf, aa0,aa1,aa2,aa3,aa4,aa5, nAx,nAy, ex0,ex1,ex2,ex3, ex4,ex5)`],
    [`fold1(Pm, pf, bb0,bb1,bb2,bb3,bb4,bb5, kv0,kv1,kv2,kv3, ex4,ex5)`, `fold1(Pm, pf, bb0,bb1,bb2,bb3,bb4,bb5, vkxX,vkxY, ex0,ex1,ex2,ex3, ex4,ex5)`],
    [`fold1(Pm, pf, uu0,uu1,uu2,uu3,uu4,uu5, kc0,kc1,kc2,kc3, ex4,ex5)`, `fold1(Pm, pf, uu0,uu1,uu2,uu3,uu4,uu5, Cx,Cy, ex0,ex1,ex2,ex3, ex4,ex5)`],
  ];
  for (const [from, to] of replacements) out = out.split(from).join(to);
  if (/\bk[vcng][0-3]\b/.test(out)) throw new Error(`${mode}: hoisted k* variables still present`);
  return out;
}

function measureWindow(lo, hi) {
  const baseSrc = genChunkGB(lo, hi, { expectOutHex: binToHex(outBlobGB(hi)) });
  const srcs = {
    current: baseSrc,
    'dehoist-inline': dehoistSource(baseSrc, 'dehoist-inline'),
    'lineFz-faithful': dehoistSource(baseSrc, 'lineFz-faithful'),
  };
  const inBlob = inBlobGB(lo, hi);
  const out = { window: [lo, hi], K: hi - lo, inBlobBytes: inBlob.length };
  for (const [variant, src] of Object.entries(srcs)) {
    let compiled = null;
    try {
      compiled = compileSource(src, `fixline_${variant.replace(/[^a-z0-9]/gi, '_')}_${lo}_${hi}`);
      const optimized = optimizeBody(compiled.redeem, `fixline_${variant.replace(/[^a-z0-9]/gi, '_')}_${lo}_${hi}`);
      const run = evaluateBody(optimized.body, inBlob);
      out[variant] = {
        sourceBytes: Buffer.byteLength(src, 'utf8'),
        rawBodyBytes: optimized.rawBytes,
        optimizerApplied: optimized.applied,
        optimizedDeltaBytes: optimized.optimizedDeltaBytes ?? 0,
        ...run,
      };
    } catch (e) {
      out[variant] = {
        sourceBytes: Buffer.byteLength(src, 'utf8'),
        compileOrRunError: String(e?.message ?? e).slice(0, 500),
      };
    } finally {
      if (compiled?.tempRoot) rmSync(compiled.tempRoot, { recursive: true, force: true });
    }
  }
  return out;
}

const pairingRoot = resolve(pairingDir, '..', '..', '..');
const toolPkg = packageVersion(join(resolve('.'), 'package.json'));
const liveBuildPkg = packageVersion(join(resolve(pairingDir, '..', '..'), 'package.json'));
const results = windows.map(([lo, hi]) => measureWindow(lo, hi));

for (const r of results) {
  for (const variant of ['dehoist-inline', 'lineFz-faithful']) {
    if (!r.current?.accepted || !r[variant]?.accepted) continue;
    r[`${variant}-delta-vs-current`] = {
      bodyBytes: r[variant].bodyBytes - r.current.bodyBytes,
      sourceBytes: r[variant].sourceBytes - r.current.sourceBytes,
      opCost: r[variant].opCost - r.current.opCost,
      instr: r[variant].instr - r.current.instr,
      pushedBytes: r[variant].pushedBytes - r.current.pushedBytes,
    };
  }
}

const summary = {
  ok: results.every((r) => r.current?.accepted && r['dehoist-inline']?.accepted),
  pairingDir,
  windows,
  env: {
    SZ_ALLAFF: process.env.SZ_ALLAFF ?? '',
    SEAMNARROW: process.env.SEAMNARROW ?? '',
    UNW: process.env.UNW ?? '',
    CDNW: process.env.CDNW ?? '',
    CDWIDTH: process.env.CDWIDTH ?? '',
    KSPEC: process.env.KSPEC ?? '',
    NITS: process.env.NITS ?? '',
    FIXLINE_OPTIMIZE: useOptimizer ? '1' : '0',
    FIXLINE_PAD_NOP: String(padNopBytes),
    FIXLINE_PAD_PUSH: String(padPushBytes),
  },
  liveC7Evidence: {
    gen_miller_gb3_9k7: 'prologue defines kn0..kc3 = point * ex0..3 once per chunk',
    t3_shared3_9k7: 'fold1 consumes precomputed point*ex products',
    NW0: Array.isArray(NW) ? NW[0] : NW,
    stateBytes: STATE_BYTES,
    wdatBytesFirstWindow: windows[0] ? wdatBytesForChunk(windows[0][0]) : null,
  },
  provenance: {
    verifierCashCommit: gitShort(vcRepoPath('')),
    pairingWorktreeCommit: gitShort(pairingRoot),
    verifierCashDirty: gitStatus(vcRepoPath('')),
    pairingWorktreeDirtyCount: gitStatus(pairingRoot).length,
    libauthPackageVersion: toolPkg ? JSON.parse(readFileSync(join(resolve('.'), 'package.json'), 'utf8')).dependencies?.['@bitauth/libauth'] ?? toolPkg : null,
    liveBuildPackageVersion: liveBuildPkg,
    node: process.version,
  },
  evidenceClass: 'source-level VM spike over live c7 generated body; not a full transaction rebuild and not a new saving',
  results,
};

console.log(JSON.stringify(summary, null, 2));
