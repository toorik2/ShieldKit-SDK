// Lossless two-step Schwartz-Zippel transcript for the normalized C7
// trajectory. Odd Miller anchors are eliminated by polynomial composition:
//
//   (R_i^2 F_i)^2 F_(i+1) - R_(i+2) = Q_i' P12.
//
// This is intentionally a transcript/state module, not a candidate switch.
// An emitter must consume `windows` directly; adapting a v1 step emitter and
// merely dropping its odd-chain bytes would reintroduce an unbound scalar.
import * as field from '../../../../build/chunked/pairing/_szmath.mjs';
import { f12limbs } from '../../../../build/chunked/pairing/_millermath.mjs';
import * as normalized from './normalized-szmath.mjs';

export const TAG_GAMMA_V2 = Buffer.from('BN254-SZMILLER-ROLL/gamma/v2', 'ascii');
export const TAG_GAMMA_FIN_V2 = Buffer.from('BN254-SZMILLER-ROLL/gamma-final/v2', 'ascii');
export const TAG_Z_V2 = Buffer.from('BN254-SZMILLER-ROLL/z/v2', 'ascii');
// The deployable seven-input topology already has a real singleton genesis
// step. Keeping that step intact avoids an ECIP/root rewrite; the following
// singleton produces the first even boundary, and every remaining interior
// pair is composed. These domain tags make that distinct transcript explicit.
export const TAG_GAMMA_MIXED_V2 = Buffer.from('BN254-SZMILLER-ROLL/gamma/v2/mixed-0-1', 'ascii');
export const TAG_GAMMA_FIN_MIXED_V2 = Buffer.from('BN254-SZMILLER-ROLL/gamma-final/v2/mixed-0-1', 'ascii');
export const TAG_Z_MIXED_V2 = Buffer.from('BN254-SZMILLER-ROLL/z/v2/mixed-0-1', 'ascii');
// Scalar-endpoint FS (C7_SCALAR_ENDPOINT=1): each Miller anchor is bound as a
// single field element bind=∑ F_i·W^i (W fixed), not the full 12-limb tower.
export const TAG_GAMMA_MIXED_V3_SCALAR = Buffer.from('BN254-SZMILLER-ROLL/gamma/v3/mixed-0-1-scalar', 'ascii');
export const TAG_GAMMA_FIN_MIXED_V3_SCALAR = Buffer.from('BN254-SZMILLER-ROLL/gamma-final/v3/mixed-0-1-scalar', 'ascii');
export const TAG_Z_MIXED_V3_SCALAR = Buffer.from('BN254-SZMILLER-ROLL/z/v3/mixed-0-1-scalar', 'ascii');
// Dens-rich: fixed VK G2 limbs replaced by hash256(serLimbs(vk14)) in stmt block (−416 B).
export const TAG_GAMMA_MIXED_V4_VKDIG = Buffer.from('BN254-SZ/g/v4-s-vk', 'ascii');
export const TAG_GAMMA_FIN_MIXED_V4_VKDIG = Buffer.from('BN254-SZ/gf/v4-s-vk', 'ascii');
export const TAG_Z_MIXED_V4_VKDIG = Buffer.from('BN254-SZ/z/v4-s-vk', 'ascii');
// gen6-4exec deployable gen-absorb: singleton head through Miller step 4, then pairs.
export const TAG_GAMMA_MIXED_GEN64 = Buffer.from('BN254-SZMILLER-ROLL/gamma/v2/mixed-gen64-s4', 'ascii');
export const TAG_GAMMA_FIN_MIXED_GEN64 = Buffer.from('BN254-SZMILLER-ROLL/gamma-final/v2/mixed-gen64-s4', 'ascii');
export const TAG_Z_MIXED_GEN64 = Buffer.from('BN254-SZMILLER-ROLL/z/v2/mixed-gen64-s4', 'ascii');

/** Fixed nothing-up-my-sleeve weight for z-independent Fp12→Fp bind. */
export const SCALAR_ENDPOINT_WEIGHT = 7n;

/** bind(F) = ∑ F_i · W^i mod P — 32-byte FS / endpoint payload. */
export const scalarBindLimbs = (limbs, weight = SCALAR_ENDPOINT_WEIGHT) => {
  let bind = 0n;
  let wpow = 1n;
  for (const limb of limbs) {
    bind = field.madd(bind, field.mmul(field.mod(BigInt(limb)), wpow));
    wpow = field.mmul(wpow, weight);
  }
  return bind;
};

const serLimbs = (values) => Buffer.concat(values.map(field.be32));

export const composeRanges = (trace, ranges) => {
  if (!Array.isArray(ranges) || ranges.length === 0) throw new Error('composed windows require nonempty ranges');
  let expectedStart = 0;
  return ranges.map(([start, end], index) => {
    if (!Number.isInteger(start) || !Number.isInteger(end) || start !== expectedStart || end <= start || end > trace.steps.length || end - start > 2) {
      throw new Error(`invalid composed range ${index}: [${start},${end})`);
    }
    expectedStart = end;
    return {
      start,
      end,
      // These are the exact, statement-derived factor polynomials. Any
      // interior anchor of a two-step range is deliberately absent.
      factors: trace.statementFactors.slice(start, end),
      input: field.towerToPoly(trace.chain[start]),
      output: field.towerToPoly(trace.chain[end]),
    };
  }).map((window, index, windows) => {
    if (index === windows.length - 1 && window.end !== trace.steps.length) {
      throw new Error(`composed ranges stop at ${window.end}, expected ${trace.steps.length}`);
    }
    return window;
  });
};

export const composeWindows = (trace) => composeRanges(trace,
  Array.from({ length: Math.ceil(trace.steps.length / 2) }, (_, index) => {
    const start = index * 2;
    return [start, Math.min(start + 2, trace.steps.length)];
  }));

// singletonHeadEnd: Miller step where the singleton head ends and pure pairs begin.
// Stock mixed (PF6/PF7): 2 → windows [0,1],[1,2], then pairs from 2.
// gen6-4exec gen-absorb: 4 → four singletons [0,1]..[3,4], then pairs from 4
// so genChunk(0, genHi) can emit the genesis head without composed-pair kernels.
export const mixedGenesisRanges = (stepCount, singletonHeadEnd = 2) => {
  if (!Number.isInteger(stepCount) || stepCount < 3 || stepCount % 2 === 0) {
    throw new Error(`mixed composed schedule requires an odd step count >= 3, got ${stepCount}`);
  }
  if (!Number.isInteger(singletonHeadEnd) || singletonHeadEnd < 1 || singletonHeadEnd >= stepCount - 1
      || singletonHeadEnd % 1 !== 0) {
    throw new Error(`invalid mixed singleton head end ${singletonHeadEnd}`);
  }
  const singles = Array.from({ length: singletonHeadEnd }, (_, index) => [index, index + 1]);
  const pairStart = singletonHeadEnd;
  // pairStart must be even so remaining pairs land on even boundaries through stepCount-1.
  if (pairStart % 2 !== 0) {
    throw new Error(`mixed singleton head end ${singletonHeadEnd} must be even for pure-pair body`);
  }
  const pairs = Array.from({ length: (stepCount - 1 - pairStart) / 2 }, (_, index) => {
    const start = pairStart + index * 2;
    return [start, start + 2];
  });
  return [
    ...singles,
    ...pairs,
    [stepCount - 1, stepCount],
  ];
};

export const composeMixedGenesisWindows = (trace, singletonHeadEnd = 2) =>
  composeRanges(trace, mixedGenesisRanges(trace.steps.length, singletonHeadEnd));

export const windowLhs = (window) => {
  let value = field.pmul(window.input, window.input);
  for (const factor of window.factors[0]) value = field.pmul(value, factor);
  if (window.factors.length === 2) {
    value = field.pmul(value, value);
    for (const factor of window.factors[1]) value = field.pmul(value, factor);
  }
  return value;
};

export const rollGammaV2 = (statement, transcriptAnchors) => {
  return rollGammaTranscript(statement, transcriptAnchors, TAG_GAMMA_V2, TAG_GAMMA_FIN_V2);
};

const rollGammaTranscript = (statement, transcriptAnchors, tag = TAG_GAMMA_V2, finalTag = TAG_GAMMA_FIN_V2) => {
  // statement: bigint[] (serLimbs) or pre-serialized Buffer/Uint8Array (vk-digest packing)
  const stmtBlock = Buffer.isBuffer(statement) || statement instanceof Uint8Array
    ? Buffer.from(statement)
    : serLimbs(statement);
  const blocks = [stmtBlock, ...transcriptAnchors.map(serLimbs)];
  let h = field.hash256(tag);
  const hs = [h];
  for (let index = 0; index < blocks.length; index += 1) {
    h = field.hash256(Buffer.concat([h, field.be4(index), field.be4(blocks[index].length), blocks[index]]));
    hs.push(h);
  }
  h = field.hash256(Buffer.concat([h, finalTag, field.be4(blocks.length)]));
  hs.push(h);
  return {
    gamma: field.mod(BigInt(`0x${h.toString('hex')}`)),
    hs,
    blockCount: blocks.length,
    blockSizes: blocks.map((block) => block.length),
  };
};

export const honestBigQV2 = (windows, gamma) => {
  let bigQ = [0n];
  let weight = 1n;
  const quotients = [];
  for (const window of windows) {
    const divided = field.pdivP12(field.psub(windowLhs(window), window.output));
    if (divided.r.some((coefficient) => coefficient !== 0n)) {
      throw new Error(`composed S-Z relation has nonzero P12 remainder at steps [${window.start},${window.end})`);
    }
    quotients.push(divided.q);
    bigQ = field.padd(bigQ, field.pscale(divided.q, weight));
    weight = field.mmul(weight, gamma);
  }
  return { bigQ, quotients };
};

export const rollZV2 = (gamma, bigQ) => {
  return rollZTranscript(gamma, bigQ, TAG_Z_V2);
};

const rollZTranscript = (gamma, bigQ, tag = TAG_Z_V2) => {
  const payload = Buffer.concat([tag, field.be32(gamma), serLimbs(bigQ)]);
  return { z: field.mod(BigInt(`0x${field.hash256(payload).toString('hex')}`)), payloadBytes: payload.length };
};

export const aggregatedIdentityV2 = (windows, anchors, bigQ, gamma, z) => {
  const anchorZ = anchors.map((anchor) => field.peval(anchor, z));
  let lhs = 0n;
  let rhsAnchors = 0n;
  let weight = 1n;
  const products = [];
  for (let index = 0; index < windows.length; index += 1) {
    let product = field.mmul(anchorZ[index], anchorZ[index]);
    for (const factor of windows[index].factors[0]) product = field.mmul(product, field.peval(factor, z));
    if (windows[index].factors.length === 2) {
      product = field.mmul(product, product);
      for (const factor of windows[index].factors[1]) product = field.mmul(product, field.peval(factor, z));
    }
    products.push(product);
    lhs = field.madd(lhs, field.mmul(weight, product));
    rhsAnchors = field.madd(rhsAnchors, field.mmul(weight, anchorZ[index + 1]));
    weight = field.mmul(weight, gamma);
  }
  const rhs = field.madd(field.mmul(field.peval(bigQ, z), field.peval(field.P12, z)), rhsAnchors);
  return { lhs, rhs, holds: lhs === rhs, anchorZ, products };
};

let cached = null;
export function trajectory() {
  if (cached) return cached;
  const v1 = normalized.trajectory();
  const windows = composeWindows(v1);
  const anchorIndices = [...windows.map((window) => window.start), v1.steps.length];
  const anchors = anchorIndices.map((index) => field.towerToPoly(v1.chain[index]));
  // The endpoint witness is the canonical Fp12 limb encoding consumed by the
  // BCH executor. Hash that exact encoding. The polynomial basis below is an
  // algebraic change of coordinates for S-Z evaluation, not a second wire
  // representation that should be re-witnessed or re-hashed on chain.
  const transcriptAnchors = anchorIndices.map((index) => f12limbs(v1.chain[index]).map(field.mod));
  const rolling = rollGammaV2(v1.stmtLimbs, transcriptAnchors);
  const { bigQ, quotients } = honestBigQV2(windows, rolling.gamma);
  const challenge = rollZV2(rolling.gamma, bigQ);
  const id = aggregatedIdentityV2(windows, anchors, bigQ, rolling.gamma, challenge.z);
  if (!id.holds) throw new Error('composed S-Z trajectory invariant failed');
  cached = {
    ...v1,
    v1,
    windows,
    anchors,
    transcriptAnchors,
    anchorIndices,
    quotients,
    seamH: rolling.hs,
    blockCount: rolling.blockCount,
    blockSizes: rolling.blockSizes,
    gamma: rolling.gamma,
    z: challenge.z,
    bigQ,
    bigQz: field.peval(bigQ, challenge.z),
    anchorZ: id.anchorZ,
    windowProducts: id.products,
    id,
    transcriptVersion: 2,
  };
  return cached;
}

let mixedCached = null;
let mixedCachedKey = '';
// Variants that deepen the mixed singleton head to genHi=4 (Ideal genP=2).
// MUST be readable at module-load time: gen_miller_sz freezes trajectory() once
// when mixed-sz is imported, before composed-window-plan can set env mirrors.
const GEN_ABSORB_HEAD4 = new Set([
  'gen6-4exec',
  '6in-gen2-8877',
  '7in-gen2-flat',
]);

export function mixedGenesisTrajectory() {
  // Deployable gen-absorb (genHi=4 / Ideal genP=2) deepens the singleton head so
  // genChunk can own Miller [0,4). Prefer C7_IDEAL_VARIANT (set by adapter before
  // any import). C7_SINGLETON_HEAD_END is a secondary override.
  const disabled = process.env.C7_FORCE_IDEAL_WINDOWS === '0';
  const headEnv = Number(process.env.C7_SINGLETON_HEAD_END || '');
  const variantAbsorb = !disabled && GEN_ABSORB_HEAD4.has(process.env.C7_IDEAL_VARIANT || '');
  const singletonHeadEnd = Number.isInteger(headEnv) && headEnv >= 2 && headEnv % 2 === 0
    ? headEnv
    : (variantAbsorb ? 4 : 2);
  const gen64 = singletonHeadEnd >= 4;
  const cacheKey = `${singletonHeadEnd}`;
  if (mixedCached && mixedCachedKey === cacheKey) return mixedCached;
  const v1 = normalized.trajectory();
  const windows = composeMixedGenesisWindows(v1, singletonHeadEnd);
  const anchorIndices = [...windows.map((window) => window.start), v1.steps.length];
  const anchors = anchorIndices.map((index) => field.towerToPoly(v1.chain[index]));
  const scalarEndpoint = process.env.C7_SCALAR_ENDPOINT === '1';
  if (scalarEndpoint && gen64) {
    throw new Error('C7_SCALAR_ENDPOINT is only supported on stock mixed (singletonHeadEnd=2) PF7 path');
  }
  const fullAnchors = anchorIndices.map((index) => f12limbs(v1.chain[index]).map(field.mod));
  // Scalar mode: FS binds one field element per anchor (z-independent weighted sum).
  const transcriptAnchors = scalarEndpoint
    ? fullAnchors.map((limbs) => [scalarBindLimbs(limbs)])
    : fullAnchors;
  // Dens-rich packing: replace 14 fixed VK limbs (alpha..delta) with hash256(serLimbs).
  // deployedStatementLimbs: [A2,B4,C2,vkx2, alpha2,beta4,gamma4,delta4, c12,ci12,w*]
  const VK_DIGEST = process.env.C7_VK_DIGEST === '1' && scalarEndpoint && !gen64;
  const PRE_VK = 10;
  const VK_LIMBS = 14;
  let stmtForGamma = v1.stmtLimbs;
  let vkDigestHex = null;
  // dens-rich: last post limb is L17 wsel ∈{0,1,2} — pack as 1 B (not BE32).
  const WSEL_U8 = process.env.C7_WSEL_U8 === '1' && scalarEndpoint;
  if (VK_DIGEST) {
    if (v1.stmtLimbs.length < PRE_VK + VK_LIMBS) {
      throw new Error(`C7_VK_DIGEST: stmtLimbs short len=${v1.stmtLimbs.length}`);
    }
    const pre = v1.stmtLimbs.slice(0, PRE_VK);
    const vk = v1.stmtLimbs.slice(PRE_VK, PRE_VK + VK_LIMBS);
    const post = v1.stmtLimbs.slice(PRE_VK + VK_LIMBS);
    const dig = field.hash256(serLimbs(vk));
    vkDigestHex = dig.toString('hex');
    let postBytes;
    if (WSEL_U8 && post.length >= 1) {
      const wsel = post[post.length - 1];
      if (wsel !== 0n && wsel !== 1n && wsel !== 2n) throw new Error(`C7_WSEL_U8 bad wsel ${wsel}`);
      postBytes = Buffer.concat([serLimbs(post.slice(0, -1)), Buffer.from([Number(wsel)])]);
    } else {
      postBytes = serLimbs(post);
    }
    stmtForGamma = Buffer.concat([serLimbs(pre), dig, postBytes]);
  } else if (WSEL_U8) {
    // non-vkdig: full stmtLimbs with trailing wsel as 1 B
    const limbs = v1.stmtLimbs;
    const wsel = limbs[limbs.length - 1];
    if (wsel !== 0n && wsel !== 1n && wsel !== 2n) throw new Error(`C7_WSEL_U8 bad wsel ${wsel}`);
    stmtForGamma = Buffer.concat([serLimbs(limbs.slice(0, -1)), Buffer.from([Number(wsel)])]);
  }
  const gammaTag = gen64
    ? TAG_GAMMA_MIXED_GEN64
    : (VK_DIGEST ? TAG_GAMMA_MIXED_V4_VKDIG
      : (scalarEndpoint ? TAG_GAMMA_MIXED_V3_SCALAR : TAG_GAMMA_MIXED_V2));
  const gammaFinTag = gen64
    ? TAG_GAMMA_FIN_MIXED_GEN64
    : (VK_DIGEST ? TAG_GAMMA_FIN_MIXED_V4_VKDIG
      : (scalarEndpoint ? TAG_GAMMA_FIN_MIXED_V3_SCALAR : TAG_GAMMA_FIN_MIXED_V2));
  const zTag = gen64
    ? TAG_Z_MIXED_GEN64
    : (VK_DIGEST ? TAG_Z_MIXED_V4_VKDIG
      : (scalarEndpoint ? TAG_Z_MIXED_V3_SCALAR : TAG_Z_MIXED_V2));
  const rolling = rollGammaTranscript(stmtForGamma, transcriptAnchors, gammaTag, gammaFinTag);
  const { bigQ, quotients } = honestBigQV2(windows, rolling.gamma);
  const challenge = rollZTranscript(rolling.gamma, bigQ, zTag);
  const id = aggregatedIdentityV2(windows, anchors, bigQ, rolling.gamma, challenge.z);
  if (!id.holds) throw new Error('mixed composed S-Z trajectory invariant failed');
  mixedCachedKey = cacheKey + (scalarEndpoint ? ':scalar' : '') + (VK_DIGEST ? ':vkdig' : '') + (WSEL_U8 ? ':wselu8' : '');
  mixedCached = {
    ...v1,
    v1,
    windows,
    anchors,
    transcriptAnchors,
    fullAnchors,
    anchorIndices,
    quotients,
    seamH: rolling.hs,
    blockCount: rolling.blockCount,
    blockSizes: rolling.blockSizes,
    gamma: rolling.gamma,
    z: challenge.z,
    bigQ,
    bigQz: field.peval(bigQ, challenge.z),
    anchorZ: id.anchorZ,
    windowProducts: id.products,
    id,
    transcriptVersion: gen64 ? '2-mixed-gen64-s4'
      : (VK_DIGEST ? (WSEL_U8 ? '4-mixed-scalar-vkdig-wselu8' : '4-mixed-scalar-vkdig')
        : (scalarEndpoint ? '3-mixed-scalar-endpoint' : '2-mixed-genesis')),
    singletonHeadEnd,
    gammaTag,
    gammaFinTag,
    zTag,
    scalarEndpoint,
    vkDigest: VK_DIGEST,
    vkDigestHex,
    wselU8: WSEL_U8,
  };
  return mixedCached;
}
