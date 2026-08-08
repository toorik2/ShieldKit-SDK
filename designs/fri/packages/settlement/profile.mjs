/**
 * Product FRI profile — param set + profile-fixed role lock freeze.
 *
 * Plan: locks compile from profile/params only; proof/witness only in unlocks.
 * Same role locking hashes for deposit|transfer|withdrawal under one profile.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** Product profile pin (floor-oriented; domain pad may apply at prove time). */
export const PRODUCT_PROFILE = Object.freeze({
  id: 'shieldkit-fri-product-v1',
  relationId: 'shieldkit-pool-action-fri-v1',
  /** Product tip: state@0 + FRI roles@1..19 (roleIndexBase=1). */
  topologyId: 'fri-sound-lean-fused-state0-v1',
  roleIndexBase: 1,
  /** Assembly params for measured-green product path (floor pad separate). */
  assemble: Object.freeze({
    depth: 4,
    blowup: 32,
    nq: 8,
    grind: 8,
    foldStep: 3,
    deep: true,
  }),
  /** Target production floor (may require 8^m domain pad). */
  floor: Object.freeze({
    depth: 32,
    blowup: 2048,
    nq: 8,
    grind: 24,
    foldStep: 3,
    deep: true,
  }),
  roleCount: 19,
});

export function profileIdFromProduct(profile = PRODUCT_PROFILE) {
  const body = JSON.stringify({
    id: profile.id,
    relationId: profile.relationId,
    topologyId: profile.topologyId,
    roleIndexBase: profile.roleIndexBase ?? 1,
    assemble: profile.assemble,
    floor: profile.floor,
    roleCount: profile.roleCount,
  });
  return createHash('sha256').update(body).digest('hex');
}

/**
 * Extract ordered role locking hexes + redeem hashes from a sound assembly artifact.
 */
export function extractRoleLocks(assemblyPathOrObj) {
  const raw =
    typeof assemblyPathOrObj === 'string'
      ? JSON.parse(readFileSync(assemblyPathOrObj, 'utf8'))
      : assemblyPathOrObj;
  const roles = raw.roleHex || raw.roles;
  if (!raw.roleHex?.length) {
    throw new Error('assembly missing roleHex (materialized locks)');
  }
  const locks = raw.roleHex.map((r, i) => ({
    index: i,
    role: r.role,
    lockingHex: String(r.lockingHex).toLowerCase(),
    redeemSha256: createHash('sha256')
      .update(Buffer.from(r.redeemBytecodeHex, 'hex'))
      .digest('hex'),
    redeemBytes: r.redeemBytes ?? r.redeemBytecodeHex.length / 2,
  }));
  return {
    productionVerifiers: raw.productionVerifiers === true,
    placeholder: raw.placeholder === true,
    kind: raw.kind,
    friParams: raw.friParams,
    depth: raw.depth,
    locks,
    lockingHexes: locks.map((l) => l.lockingHex),
    redeemSha256s: locks.map((l) => l.redeemSha256),
    lockSetSha256: createHash('sha256')
      .update(locks.map((l) => l.lockingHex).join('|'))
      .digest('hex'),
  };
}

/**
 * Assert two lock sets are identical (product profile-fixed requirement).
 */
export function assertSameRoleLocks(a, b, label = 'locks') {
  if (a.lockingHexes.length !== b.lockingHexes.length) {
    throw new Error(
      `${label}: role count ${a.lockingHexes.length} != ${b.lockingHexes.length}`,
    );
  }
  for (let i = 0; i < a.lockingHexes.length; i += 1) {
    if (a.lockingHexes[i] !== b.lockingHexes[i]) {
      throw new Error(
        `${label}: role[${i}] locking drift ` +
          `${a.locks[i]?.role}: ${a.redeemSha256s[i].slice(0, 12)} vs ${b.redeemSha256s[i].slice(0, 12)}`,
      );
    }
  }
  return true;
}

/**
 * Compare D/T/W assemblies for profile-fixed locks.
 * @returns {{ ok: boolean, lockSetSha256?: string, drifts: object[] }}
 */
export function compareKindLocks(pathsByKind) {
  const extracted = {};
  for (const [kind, p] of Object.entries(pathsByKind)) {
    if (!existsSync(p)) {
      return { ok: false, drifts: [{ kind, error: `missing ${p}` }] };
    }
    extracted[kind] = extractRoleLocks(p);
  }
  const kinds = Object.keys(extracted);
  const drifts = [];
  const base = extracted[kinds[0]];
  for (const kind of kinds.slice(1)) {
    const other = extracted[kind];
    for (let i = 0; i < base.lockingHexes.length; i += 1) {
      if (base.lockingHexes[i] !== other.lockingHexes[i]) {
        drifts.push({
          index: i,
          role: base.locks[i].role,
          kinds: [kinds[0], kind],
          redeemSha256: [base.redeemSha256s[i], other.redeemSha256s[i]],
          lockingHex: [base.lockingHexes[i], other.lockingHexes[i]],
        });
      }
    }
  }
  return {
    ok: drifts.length === 0,
    lockSetSha256: base.lockSetSha256,
    kinds,
    drifts,
    extracted,
  };
}

/**
 * Freeze product locks from one assembly into evidence/production/PROFILE_LOCKS.json
 */
export function freezeProfileLocks(assemblyPath, outDir) {
  mkdirSync(outDir, { recursive: true });
  const ext = extractRoleLocks(assemblyPath);
  if (!ext.productionVerifiers || ext.placeholder) {
    throw new Error('cannot freeze locks from non-production assembly');
  }
  const doc = {
    schema: 'shieldkit-fri-profile-locks-v1',
    profileId: profileIdFromProduct(),
    productProfile: PRODUCT_PROFILE,
    sourceAssembly: path.relative(ROOT, assemblyPath),
    kind: ext.kind,
    friParams: ext.friParams,
    depth: ext.depth,
    lockSetSha256: ext.lockSetSha256,
    locks: ext.locks,
    frozenAt: new Date().toISOString(),
    note:
      'Role locking scripts frozen for product common-parent. All actions must match lockSetSha256.',
  };
  const out = path.join(outDir, 'PROFILE_LOCKS.json');
  writeFileSync(out, JSON.stringify(doc, null, 2) + '\n');
  return doc;
}

/**
 * Run product fixed-lock assemble for one kind (python, VC_PRODUCT_FIXED_LOCKS=1).
 */
export function assembleProductKind(kind, { outPath, seed = 1, profile = PRODUCT_PROFILE.assemble } = {}) {
  const py = path.join(ROOT, 'packages/settlement/python/assemble_sound_settlement.py');
  const args = [
    py,
    kind,
    '--depth', String(profile.depth),
    '--nq', String(profile.nq),
    '--blowup', String(profile.blowup),
    '--grind', String(profile.grind),
    '--fold-step', String(profile.foldStep),
    '--seed', String(seed),
    '--out', outPath,
  ];
  const roleIndexBase = PRODUCT_PROFILE.roleIndexBase ?? 1;
  const r = spawnSync('python3', args, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    env: {
      ...process.env,
      VC_PRODUCT_FIXED_LOCKS: '1',
      VC_ROLE_INDEX_BASE: String(roleIndexBase),
      VC_SKIP_PROOF_VERIFY: process.env.VC_SKIP_PROOF_VERIFY || '1',
    },
    timeout: 0,
  });
  return {
    status: r.status,
    ok: r.status === 0 && existsSync(outPath),
    stdoutTail: (r.stdout || '').slice(-2000),
    stderrTail: (r.stderr || '').slice(-1500),
    roleIndexBase,
  };
}
