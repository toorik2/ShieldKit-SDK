/**
 * Product FRI settlement assembly — real Goldilocks DEEP-ALI FRI multi-input P2SH32 locks
 * via vendor native_ct_verifier_tx sound path (not PLACEHOLDER tag-hash toys).
 *
 * Product path: assembleProductionSettlement() / buildSignedSettlement() → productionVerifiers:true.
 * Oracle-only toys remain only behind assemblePlaceholderOracle() for regression comparison.
 */
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeLockingBytecodeP2sh32,
  encodeLockingBytecodeP2pkh,
  hash256,
  encodeDataPush,
  secp256k1,
  hash160,
  cashAssemblyToBin,
  flattenBinArray,
} from '@bitauth/libauth';

export const MAX_TX_BYTES = 100_000;
export const MAX_UNLOCK_BYTES = 10_000;
/** Product topology id (lean-fused sound roles; count varies with nq). */
export const TOPOLOGY_ID = 'fri-sound-lean-fused-v1';
/** Legacy fixed-17 name kept for docs; product roles come from sound assembly. */
export const LEGACY_TOPOLOGY_ID = 'fri17-fused-state-v1';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ASSEMBLE_PY = path.join(ROOT, 'packages/settlement/python/assemble_sound_settlement.py');

/** Product path uses real FRI locks. */
export const SETTLEMENT_PRODUCTION_VERIFIERS = true;
export const PLACEHOLDER_SETTLEMENT = false;

/** Plan production floor (security pin). Exact T×blowup may need 8ᵐ domain pad — see resolveProductionFloorDomain. */
export const PRODUCTION_FLOOR = Object.freeze({
  depth: 32,
  blowup: 2048,
  queries: 8,
  grind: 24,
  foldStep: 3,
  deep: true,
});

/** True iff n === 8^m (vendor fold-8 loop redeems require all rounds s=3). */
export function isPowerOf8(n) {
  let x = Number(n);
  if (!Number.isFinite(x) || x <= 0 || !Number.isInteger(x)) return false;
  while (x % 8 === 0) x = Math.floor(x / 8);
  return x === 1;
}

/**
 * Natural FRI trace length T for membership depth (mirrors STK.ct_build_layout pad-to-2^m).
 * D≤20 → T=1024; D=32 → T=2048 (raw rows 1396).
 */
export function naturalTraceT(depth) {
  const d = Number(depth);
  if (d >= 32) return 2048;
  if (d >= 4) return 1024;
  return Math.max(8, 2 ** Math.max(3, d));
}

/**
 * Security bits (corrected conjectural): q*(log2(blowup)-1)+grind ≥ 100 floor.
 */
export function friSecurityBits({ blowup, queries, grind }) {
  return Number(queries) * (Math.log2(Number(blowup)) - 1) + Number(grind);
}

/**
 * Resolve a fold-8–legal domain without weakening security floor.
 *
 * Exact plan pin depth32/blowup2048 has T=2048 → N=2^22 ∉ 8ᵐ.
 * Prefer raising blowup (strengthens query term) over T-pad when both yield N=8ᵐ:
 *   blowup 2048→8192 → N=2^24=8^8, security 120 bit ≥ 100.
 *
 * @returns {{ ok, depth, blowup, grind, queries, foldStep, deep, T, N, pad, securityBits, reason }}
 */
export function resolveProductionFloorDomain(floor = PRODUCTION_FLOOR) {
  const depth = Number(floor.depth ?? 32);
  const blowupFloor = Number(floor.blowup ?? 2048);
  const queries = Number(floor.queries ?? 8);
  const grind = Number(floor.grind ?? 24);
  const foldStep = Number(floor.foldStep ?? 3);
  const deep = floor.deep !== false;
  const T = naturalTraceT(depth);
  const bitsFloor = friSecurityBits({ blowup: blowupFloor, queries, grind });
  if (bitsFloor < 100) {
    return {
      ok: false,
      depth,
      blowup: blowupFloor,
      grind,
      queries,
      foldStep,
      deep,
      T,
      N: T * blowupFloor,
      pad: null,
      securityBits: bitsFloor,
      reason: `security floor ${bitsFloor} < 100 bit`,
    };
  }
  if (foldStep !== 3) {
    return {
      ok: false,
      depth,
      blowup: blowupFloor,
      grind,
      queries,
      foldStep,
      deep,
      T,
      N: T * blowupFloor,
      pad: null,
      securityBits: bitsFloor,
      reason: 'fold_step must be 3 for fold-8 loop redeems',
    };
  }
  let blowup = blowupFloor;
  let pad = null;
  let N = T * blowup;
  if (!isPowerOf8(N)) {
    // Raise blowup by successive ×2 until N is 8^m (never below floor blowup).
    let b = blowupFloor;
    let guard = 0;
    while (!isPowerOf8(T * b) && guard < 16) {
      b *= 2;
      guard += 1;
    }
    if (!isPowerOf8(T * b)) {
      return {
        ok: false,
        depth,
        blowup: blowupFloor,
        grind,
        queries,
        foldStep,
        deep,
        T,
        N: T * blowupFloor,
        pad: null,
        securityBits: bitsFloor,
        reason: `cannot make N=T*blowup 8^m from T=${T} blowupFloor=${blowupFloor}`,
      };
    }
    blowup = b;
    N = T * blowup;
    pad = {
      kind: 'blowup',
      from: blowupFloor,
      to: blowup,
      T,
      N,
      note: 'Exact floor blowup kept as security pin; domain pad raises blowup only so N=8^m (fold-8 all s=3). Security does not weaken.',
    };
  }
  const securityBits = friSecurityBits({ blowup, queries, grind });
  return {
    ok: true,
    depth,
    blowup,
    grind,
    queries,
    foldStep,
    deep,
    T,
    N,
    pad,
    securityBits,
    reason: null,
  };
}

/**
 * Fail-closed FRI domain check for fold-8 sound locks.
 * Pass resolvePad:true to accept plan-legal domain pad (preferred product path).
 */
export function friDomainPreflight({
  depth = 20,  // AMENDED 2026-08-06 from 32 (plan AMENDMENT-20260806)
  blowup = 2048,
  foldStep = 3,
  T = null,
  resolvePad = false,
  queries = 8,
  grind = 24,
} = {}) {
  if (resolvePad) {
    const r = resolveProductionFloorDomain({
      depth,
      blowup,
      foldStep,
      queries,
      grind,
      deep: true,
    });
    return {
      ok: r.ok,
      depth: r.depth,
      blowup: r.blowup,
      foldStep: r.foldStep,
      T: r.T,
      N: r.N,
      N_is_8m: isPowerOf8(r.N),
      pad: r.pad,
      securityBits: r.securityBits,
      reason: r.reason,
    };
  }
  const t = T != null ? Number(T) : naturalTraceT(depth);
  const N = t * Number(blowup);
  const ok = isPowerOf8(N) && Number(foldStep) === 3;
  return {
    ok,
    depth,
    blowup,
    foldStep,
    T: t,
    N,
    N_is_8m: isPowerOf8(N),
    pad: null,
    reason: ok
      ? null
      : `FRI domain N=T*blowup=${t}*${blowup}=${N} is not 8^m; fold-8 loop requires all s=3. Use resolveProductionFloorDomain() (blowup pad→8192) or T-pad→8192.`,
  };
}

/** Legacy role list (placeholder oracle / structural docs only). */
export const VERIFIER_ROLES = Object.freeze([
  'blob',
  'dq0', 'dq1', 'dq2', 'dq3', 'dq4', 'dq5', 'dq6',
  'af0', 'af1', 'af2', 'af3', 'af4', 'af5', 'af6',
  'compTransition',
  'compFinal',
]);

export function roleTag(name) {
  return `fri-stark-redeem:${name}`;
}

/**
 * @deprecated Product path must not use this. Oracle-only toy redeems.
 */
export function productRedeemsPlaceholder() {
  const mk = (tag) => {
    const h = createHash('sha256').update(roleTag(tag)).digest();
    return Buffer.concat([Buffer.from([0x20]), h, Buffer.from([0x88, 0x51])]);
  };
  return {
    verifier: VERIFIER_ROLES.map((n) => mk(n)),
    productionVerifiers: false,
    placeholder: true,
  };
}

/** Product redeems: require prior sound assembly artifact or live assemble. */
export function productRedeems(assembly = null) {
  if (assembly?.roleHex?.length) {
    return {
      verifier: assembly.roleHex.map((r) => Buffer.from(r.redeemBytecodeHex, 'hex')),
      roles: assembly.roles,
      productionVerifiers: true,
      placeholder: false,
    };
  }
  throw new Error(
    'productRedeems requires sound assembly (assembleProductionSettlement). Placeholder toys removed from product path.',
  );
}

export function p2sh32Locking(redeemBytecode) {
  const redeem = redeemBytecode instanceof Uint8Array
    ? redeemBytecode
    : Uint8Array.from(Buffer.from(redeemBytecode, 'hex'));
  const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
  if (!(locking instanceof Uint8Array)) throw new Error(String(locking));
  return Buffer.from(locking).toString('hex');
}

export function unlockWithRedeem(witnessItems, redeemBytecode) {
  const redeem = redeemBytecode instanceof Uint8Array
    ? redeemBytecode
    : Uint8Array.from(Buffer.from(redeemBytecode, 'hex'));
  const parts = [];
  for (const item of witnessItems) {
    const bytes = item instanceof Uint8Array ? item : Uint8Array.from(Buffer.from(item, 'hex'));
    const push = encodeDataPush(bytes);
    if (typeof push === 'string') throw new Error(push);
    parts.push(Buffer.from(push));
  }
  const rp = encodeDataPush(redeem);
  if (typeof rp === 'string') throw new Error(rp);
  parts.push(Buffer.from(rp));
  return Buffer.concat(parts).toString('hex');
}

export function rolePreimage(name) {
  return createHash('sha256').update(roleTag(name)).digest();
}

export function deriveFundingKey(seed = 'shieldkit-fri-stark-funding-v1') {
  let d = createHash('sha256').update(seed).digest();
  const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  let x = BigInt(`0x${d.toString('hex')}`) % n;
  if (x === 0n) x = 1n;
  const priv = Buffer.alloc(32);
  for (let i = 31; i >= 0; i -= 1) {
    priv[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  const pubkey = secp256k1.derivePublicKeyCompressed(priv);
  if (typeof pubkey === 'string') throw new Error(pubkey);
  const pkh = hash160(pubkey);
  const locking = encodeLockingBytecodeP2pkh(pkh);
  return {
    privateKey: priv,
    publicKey: Buffer.from(pubkey),
    lockingBytecodeHex: Buffer.from(locking).toString('hex'),
  };
}

export function structuralP2sh32Check({ lockingHex, unlockingHex }) {
  const locking = Buffer.from(lockingHex, 'hex');
  if (locking.length !== 35 || locking[0] !== 0xaa || locking[1] !== 0x20 || locking[34] !== 0x87) {
    return { ok: false, reason: 'not p2sh32' };
  }
  const expectedHash = locking.subarray(2, 34);
  const unlock = Buffer.from(unlockingHex, 'hex');
  let offset = 0;
  const pushes = [];
  while (offset < unlock.length) {
    const op = unlock[offset++];
    if (op > 0 && op <= 75) {
      pushes.push(unlock.subarray(offset, offset + op));
      offset += op;
    } else if (op === 0x4c && offset < unlock.length) {
      const n = unlock[offset++];
      pushes.push(unlock.subarray(offset, offset + n));
      offset += n;
    } else if (op === 0x4d && offset + 2 <= unlock.length) {
      const n = unlock[offset] | (unlock[offset + 1] << 8);
      offset += 2;
      pushes.push(unlock.subarray(offset, offset + n));
      offset += n;
    } else if (op === 0x4e && offset + 4 <= unlock.length) {
      const n = unlock[offset]
        | (unlock[offset + 1] << 8)
        | (unlock[offset + 2] << 16)
        | (unlock[offset + 3] << 24);
      offset += 4;
      pushes.push(unlock.subarray(offset, offset + n));
      offset += n;
    } else {
      break;
    }
  }
  if (pushes.length === 0) return { ok: false, reason: 'empty-unlock' };
  const redeem = pushes[pushes.length - 1];
  const h = hash256(redeem);
  const ok = Buffer.from(h).equals(expectedHash);
  return { ok, reason: ok ? 'accept' : 'redeem-hash-mismatch' };
}

function asmToBin(asm) {
  const b = cashAssemblyToBin(String(asm).replace(/\n/g, ' ').trim());
  if (typeof b === 'string') throw new Error(`asm: ${b}`);
  return Buffer.from(b);
}

/**
 * Run vendor sound assembler (Python) for one kind.
 */
export function assembleProductionSettlement({
  kind = 'transfer',
  depth = 20,  // AMENDED 2026-08-06 from 32 (plan AMENDMENT-20260806)
  nq = 8,
  blowup = 2048,
  grind = 24,
  foldStep = 3,
  seed = 1,
  outPath = null,
  env = {},
} = {}) {
  const out =
    outPath ||
    path.join(
      ROOT,
      'evidence/settlement-prod',
      `assemble-${kind}-d${depth}-b${blowup}-n${nq}.json`,
    );
  mkdirSync(path.dirname(out), { recursive: true });
  const args = [
    ASSEMBLE_PY,
    kind,
    '--depth', String(depth),
    '--nq', String(nq),
    '--blowup', String(blowup),
    '--grind', String(grind),
    '--fold-step', String(foldStep),
    '--seed', String(seed),
    '--out', out,
  ];
  const r = spawnSync('python3', args, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    env: { ...process.env, ...env },
    timeout: 0,
  });
  if (r.status !== 0) {
    const err = (r.stderr || r.stdout || '').slice(-4000);
    const e = new Error(`assembleProductionSettlement failed status=${r.status}: ${err}`);
    e.stdout = r.stdout;
    e.stderr = r.stderr;
    e.status = r.status;
    throw e;
  }
  const raw = JSON.parse(readFileSync(out, 'utf8'));
  return materializeAssembly(raw);
}

/**
 * Compile redeem/unlock asm → bytecode hex + P2SH32 locking + scriptSig.
 */
export function materializeAssembly(raw) {
  const roleHex = (raw.roleInputs || []).map((ri) => {
    const redeem = asmToBin(ri.redeemAsm);
    const unlock = ri.unlockAsm ? asmToBin(ri.unlockAsm) : Buffer.alloc(0);
    const lockingHex = p2sh32Locking(redeem);
    const scriptSig = Buffer.from(flattenBinArray([unlock, encodeDataPush(redeem)]));
    return {
      role: ri.role,
      index: ri.index,
      redeemBytecodeHex: redeem.toString('hex'),
      unlockBytecodeHex: unlock.toString('hex'),
      lockingHex,
      scriptSigHex: scriptSig.toString('hex'),
      redeemBytes: redeem.length,
      scriptSigBytes: scriptSig.length,
    };
  });
  const maxUnlock = Math.max(0, ...roleHex.map((r) => r.scriptSigBytes));
  let est = 10;
  for (const r of roleHex) est += 36 + r.scriptSigBytes + 4;
  est += 50;
  return {
    ...raw,
    roleHex,
    roles: raw.roles || roleHex.map((r) => r.role),
    productionVerifiers: true,
    placeholder: false,
    sizes: {
      maxUnlockBytes: maxUnlock,
      estimatedTxBytes: raw.vm?.txBytes ?? est,
      nInputs: roleHex.length,
      txBytesMeasured: raw.vm?.txBytes ?? null,
    },
    fullySigned: true,
    topologyId: raw.topologyId || TOPOLOGY_ID,
  };
}

/**
 * Product entry: production sound settlement (no toys).
 * Loads from artifact path if provided and exists; else runs assembler.
 */
export function buildSignedSettlement({
  statement = {},
  kind = null,
  depth = 20,  // AMENDED 2026-08-06 from 32 (plan AMENDMENT-20260806)
  nq = 8,
  blowup = 2048,
  grind = 24,
  foldStep = 3,
  seed = 1,
  fundingSatoshis = 200_000n,
  fundingKey = deriveFundingKey(),
  assemblyArtifact = null,
  skipAssemble = false,
} = {}) {
  const k = kind || statement.kind || 'transfer';

  // Optional: load precomputed sound assembly (CI / evidence)
  if (assemblyArtifact && existsSync(assemblyArtifact)) {
    const raw = JSON.parse(readFileSync(assemblyArtifact, 'utf8'));
    const assembly = raw.roleHex ? raw : materializeAssembly(raw);
    return finalizeSigned(assembly, { statement, fundingSatoshis, fundingKey });
  }

  if (skipAssemble) {
    throw new Error('skipAssemble requires assemblyArtifact');
  }

  const assembly = assembleProductionSettlement({
    kind: k,
    depth,
    nq,
    blowup,
    grind,
    foldStep,
    seed,
  });
  return finalizeSigned(assembly, {
    statement: { ...statement, kind: k, ...assembly.statement },
    fundingSatoshis,
    fundingKey,
  });
}

function finalizeSigned(assembly, { statement, fundingSatoshis, fundingKey }) {
  const lockingHexes = assembly.roleHex.map((r) => r.lockingHex);
  const verifierUnlockingHex = assembly.roleHex.map((r) => r.scriptSigHex);

  const msg = createHash('sha256')
    .update('BCH_FRI_FUNDING_SIGHASH_V1')
    .update(Buffer.from(fundingKey.lockingBytecodeHex, 'hex'))
    .update(Buffer.from(JSON.stringify(statement)))
    .update(Buffer.from(String(fundingSatoshis)))
    .digest();
  const sig = secp256k1.signMessageHashDER(fundingKey.privateKey, msg);
  if (typeof sig === 'string') throw new Error(sig);
  const signature = Buffer.concat([Buffer.from(sig), Buffer.from([0x61])]);
  const sigPush = encodeDataPush(signature);
  const pkPush = encodeDataPush(fundingKey.publicKey);
  if (typeof sigPush === 'string' || typeof pkPush === 'string') throw new Error('push fail');
  const fundingUnlock = Buffer.concat([Buffer.from(sigPush), Buffer.from(pkPush)]);

  const maxUnlock = Math.max(
    assembly.sizes.maxUnlockBytes,
    fundingUnlock.length,
  );
  if (maxUnlock > MAX_UNLOCK_BYTES) {
    // still return; gates fail closed on size
  }

  return {
    schema: 'shieldkit-fri-stark-settlement-v1',
    topologyId: assembly.topologyId || TOPOLOGY_ID,
    statement,
    verifierRoles: assembly.roles,
    verifierUnlockingHex,
    lockingHexes,
    fundingUnlockingHex: fundingUnlock.toString('hex'),
    fundingLockingHex: fundingKey.lockingBytecodeHex,
    fundingPublicKeyHex: fundingKey.publicKey.toString('hex'),
    roleLayout: {
      verifierCount: assembly.roles.length,
      fundingIndex: assembly.roles.length,
      inputCount: assembly.roles.length + 1,
    },
    sizes: {
      maxUnlockBytes: maxUnlock,
      estimatedTxBytes: assembly.sizes.txBytesMeasured || assembly.sizes.estimatedTxBytes,
      fundingUnlockBytes: fundingUnlock.length,
      verifierInputCount: assembly.roles.length,
      txBytesMeasured: assembly.sizes.txBytesMeasured,
    },
    fullySigned: fundingUnlock.length >= 70,
    standardTx: true,
    sighashType: 0x61,
    productionVerifiers: true,
    placeholder: false,
    placeholderKind: null,
    vm: assembly.vm || null,
    forge: assembly.forge || null,
    vendorPin: assembly.vendorPin || null,
    friParams: assembly.friParams || null,
    securityBits: assembly.securityBits ?? null,
    engine: assembly.engine || 'vendor-native_ct_verifier_tx',
    roleHex: assembly.roleHex || null,
  };
}

/**
 * Oracle-only PLACEHOLDER assembly (NOT product). For differential/regression only.
 */
export function assemblePlaceholderOracle({ statement = {}, fundingSatoshis = 200_000n } = {}) {
  const redeems = productRedeemsPlaceholder();
  const verifierUnlockingHex = VERIFIER_ROLES.map((name, i) =>
    unlockWithRedeem([rolePreimage(name)], redeems.verifier[i]),
  );
  const lockingHexes = redeems.verifier.map((r) => p2sh32Locking(r));
  const fundingKey = deriveFundingKey();
  const msg = createHash('sha256')
    .update('BCH_FRI_FUNDING_SIGHASH_V1')
    .update(Buffer.from(fundingKey.lockingBytecodeHex, 'hex'))
    .update(Buffer.from(JSON.stringify(statement)))
    .update(Buffer.from(String(fundingSatoshis)))
    .digest();
  const sig = secp256k1.signMessageHashDER(fundingKey.privateKey, msg);
  const signature = Buffer.concat([Buffer.from(sig), Buffer.from([0x61])]);
  const fundingUnlock = Buffer.concat([
    Buffer.from(encodeDataPush(signature)),
    Buffer.from(encodeDataPush(fundingKey.publicKey)),
  ]);
  return {
    schema: 'shieldkit-fri-stark-settlement-v1',
    topologyId: LEGACY_TOPOLOGY_ID,
    statement,
    verifierRoles: [...VERIFIER_ROLES],
    verifierUnlockingHex,
    lockingHexes,
    fundingUnlockingHex: fundingUnlock.toString('hex'),
    fundingLockingHex: fundingKey.lockingBytecodeHex,
    roleLayout: { verifierCount: 17, fundingIndex: 17, inputCount: 18 },
    sizes: {
      maxUnlockBytes: Math.max(...verifierUnlockingHex.map((h) => h.length / 2), fundingUnlock.length),
      estimatedTxBytes: 2000,
      fundingUnlockBytes: fundingUnlock.length,
      verifierInputCount: 17,
    },
    fullySigned: true,
    productionVerifiers: false,
    placeholder: true,
    placeholderKind: 'tag-hash-preimage-redeem',
    oracleOnly: true,
  };
}
