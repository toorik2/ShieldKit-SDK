// Canonical witness and state material for the seven-input mixed route.
//
// This module deliberately contains no compiler or VM work.  It derives the
// data consumed by the genesis, five shared P2SH executor roles, and terminal
// from one mixed Fiat-Shamir trajectory, so an emitter cannot accidentally
// combine a composed executor with the legacy gamma/z or quotient polynomial.
import {
  mixedGenesisTrajectory,
  scalarBindLimbs,
} from './composed-window-szmath.mjs';
import { boundaryState, MIXED_EXECUTOR_RANGES } from './composed-window-plan.mjs';
import { stripChainWitness } from './composed-window-kernel.mjs';
import { PAIRFOLD_6_IDENTITY, PAIRFOLD_7_IDENTITY, PAIRFOLD_8_IDENTITY } from './pairfold-identity.mjs';
import { f12limbs } from '../../../../build/chunked/pairing/_millermath.mjs';

const HASH_BYTES = 40;
const FIELD_BYTES = 32;

const cat = (...parts) => {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};

const le = (value, width) => {
  let current = BigInt(value);
  const out = new Uint8Array(width);
  for (let index = 0; index < width; index += 1) { out[index] = Number(current & 0xffn); current >>= 8n; }
  return out;
};

const be32 = (value) => {
  let current = BigInt(value);
  const out = new Uint8Array(FIELD_BYTES);
  for (let index = FIELD_BYTES - 1; index >= 0; index -= 1) { out[index] = Number(current & 0xffn); current >>= 8n; }
  return out;
};

// The composed executor carries exactly the live Miller R point.  Do not
// derive these names from the trailing SGB fields: that suffix ends in table
// and residue values, not Rxa..Ryb.
const dynamicBlob = (boundary, state) => cat(
  le(boundary.hInt, HASH_BYTES), le(boundary.aggL, FIELD_BYTES), le(boundary.aggF, FIELD_BYTES),
  le(boundary.gp, FIELD_BYTES), le(boundary.fC, FIELD_BYTES),
  ...['Rxa', 'Rxb', 'Rya', 'Ryb'].map((name) => le(state[name], FIELD_BYTES)),
);

// `staticExecutor` is the fixed-G2 transport module; `gb3` is the underlying
// normalized state generator.  They are passed in explicitly because the
// deployable build controls their profile-sensitive imports.
export const buildComposedP2shRoute = ({ staticExecutor, gb3, field, miller }) => {
  const trace = mixedGenesisTrajectory();
  const contextBase = staticExecutor.projectionContext(1);
  const ec = field.ezCols.map((column) => field.peval(column, trace.z));
  const dot = (tower) => miller.f12limbs(tower).reduce(
    (sum, value, index) => field.madd(sum, field.mmul(BigInt(value), ec[index])), 0n,
  );
  // The 320 statement/VK bytes are unchanged. Only the transcript challenges
  // and residue evaluations are regenerated for the mixed relation.
  // Prefer the mixed transcript's own residue towers when present; fall back to
  // the underlying v1 towers only for pure research probes that lack them.
  const residueC = trace.c ?? trace.v1.c;
  const residueCi = trace.cInv ?? trace.v1.cInv;
  const context = cat(
    le(trace.gamma, FIELD_BYTES), le(trace.z, FIELD_BYTES), contextBase.slice(64, 384),
    le(dot(residueC), FIELD_BYTES), le(dot(residueCi), FIELD_BYTES),
  );
  if (context.length !== 448) throw new Error(`mixed route context width mismatch: ${context.length}`);

  const scalarEndpoint = process.env.C7_SCALAR_ENDPOINT === '1' || trace.scalarEndpoint === true;
  // Live Miller chain towers at each integer step (for endpoint bind/fn).
  const chainAt = (step) => {
    const tower = trace.v1?.chain?.[step] ?? trace.chain?.[step];
    if (!tower) throw new Error(`missing Miller chain tower at step ${step}`);
    return f12limbs(tower).map((v) => field.mod(BigInt(v)));
  };
  const roles = MIXED_EXECUTOR_RANGES.map(([start, end], role) => {
    const before = boundaryState(trace, start);
    const after = boundaryState(trace, end);
    const state = Object.fromEntries(gb3.SGB.map((name, index) => [name, BigInt(gb3.stateVal(start)[index])]));
    const next = Object.fromEntries(gb3.SGB.map((name, index) => [name, BigInt(gb3.stateVal(end)[index])]));
    const records = [];
    const appendStep = (step, includeEndpoint) => {
      const mode = Number(gb3.perStep(step).c.mode);
      const witness = gb3.wdatStep(step);
      const fixed = stripChainWitness(witness, { fixedWidth: FIELD_BYTES, factorLimbs: mode === 0 ? 2 : 4 });
      records.push(fixed);
      if (!includeEndpoint) return;
      if (scalarEndpoint) {
        // Endpoint is the Miller value AFTER this step (chain[step] is pre-step;
        // composed pairs end at step+1 for the odd half — use chain[step+1] when
        // step is odd end of a pair, else chain[step+1] for singleton step1→2).
        const endStep = step + 1;
        const limbs = chainAt(endStep);
        const bind = scalarBindLimbs(limbs);
        const fn = limbs.reduce(
          (sum, value, index) => field.madd(sum, field.mmul(value, ec[index])),
          0n,
        );
        // BE encoding (matches offline serLimbs / on-chain reverse→int)
        records.push(be32(bind), be32(fn));
      } else {
        // Full Fp12 endpoint (384 B) — trim rest of wdat to the executor width.
        const rest = witness.slice(fixed.length);
        records.push(rest.length >= 384 ? rest.slice(0, 384) : rest);
      }
    };
    // Legacy role-0 starts at 1 with a singleton [1,2); pure-pair role-0 starts
    // at an even boundary and only emits composed pairs.
    if (role === 0 && start === 1) appendStep(1, true);
    for (let step = (role === 0 && start === 1) ? 2 : start; step < end; step += 2) {
      appendStep(step, false);
      appendStep(step + 1, true);
    }
    return {
      range: [start, end],
      modes: Array.from({ length: end - start }, (_, index) => Number(gb3.perStep(start + index).c.mode)),
      stateBlob: dynamicBlob(before, state),
      expectedOut: dynamicBlob(after, next),
      records: cat(...records),
      table: staticExecutor.lineTable(start, end).bytes,
    };
  });

  const bqBlob = cat(...trace.bigQ.map(be32));
  const identity = roles.length === 4 ? PAIRFOLD_6_IDENTITY
    : roles.length === 5 ? PAIRFOLD_7_IDENTITY
      : roles.length === 6 ? PAIRFOLD_8_IDENTITY
        : (() => { throw new Error(`unsupported composed executor role count: ${roles.length}`); })();
  return {
    identity,
    trace,
    context,
    roles,
    genesisState: roles[0].stateBlob,
    terminalState: roles.at(-1).expectedOut,
    bqBlob,
    terminal: {
      genesisTag: trace.gammaTag,
      finalTag: trace.gammaFinTag,
      zTag: trace.zTag,
      blockCount: trace.blockCount,
    },
  };
};
