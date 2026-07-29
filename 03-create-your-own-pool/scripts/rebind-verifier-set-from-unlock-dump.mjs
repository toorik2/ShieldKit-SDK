#!/usr/bin/env node
/**
 * Rebuild PF7 verifier-set.bin scripts/sourceSet/settlementKernel from a densFuel
 * unlocks dump (inputs_dump.json) produced against a new verification key.
 *
 * Usage:
 *   node rebind-verifier-set-from-unlock-dump.mjs \
 *     --dump <inputs_dump.json> \
 *     --base-verifier-set <existing verifier-set.bin> \
 *     --vk-sha256 sha256:<hex> \
 *     --out <verifier-set.bin>
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  derivePf7SettlementKernelAuthority,
  encodeCanonicalPf7CarrierSourceSet,
  parsePf7CarrierAuthority,
} from '../packages/prove/authority.mjs';

const arg = (n) => {
  const i = process.argv.indexOf(`--${n}`);
  if (i === -1) return undefined;
  return process.argv[i + 1];
};

function hash256(data) {
  return createHash('sha256').update(createHash('sha256').update(data).digest()).digest();
}

function extractPushes(u) {
  const pushes = [];
  let i = 0;
  while (i < u.length) {
    const op = u[i];
    if (op >= 1 && op <= 75) {
      pushes.push(u.subarray(i + 1, i + 1 + op));
      i += 1 + op;
    } else if (op === 0x4c) {
      const n = u[i + 1];
      pushes.push(u.subarray(i + 2, i + 2 + n));
      i += 2 + n;
    } else if (op === 0x4d) {
      const n = u[i + 1] | (u[i + 2] << 8);
      pushes.push(u.subarray(i + 3, i + 3 + n));
      i += 3 + n;
    } else if (op === 0x4e) {
      const n = Number(u.readUInt32LE(i + 1));
      pushes.push(u.subarray(i + 5, i + 5 + n));
      i += 5 + n;
    } else {
      i += 1;
    }
  }
  return pushes;
}

function p2sh32Hash(lockHex) {
  const b = Buffer.from(lockHex, 'hex');
  if (b.length !== 35 || b[0] !== 0xaa || b[1] !== 0x20 || b[34] !== 0x87) {
    throw new Error(`not P2SH32 lock: ${lockHex.slice(0, 20)}…`);
  }
  return b.subarray(2, 34);
}

function redeemFor(lockHex, unlockHex) {
  const target = p2sh32Hash(lockHex);
  for (const p of extractPushes(Buffer.from(unlockHex, 'hex'))) {
    if (hash256(p).equals(target)) return p.toString('hex');
  }
  throw new Error(`no redeem for lock ${lockHex.slice(0, 20)}`);
}

const dumpPath = arg('dump');
const basePath = arg('base-verifier-set');
const vkSha = arg('vk-sha256');
const outPath = arg('out');
if (!dumpPath || !basePath || !vkSha || !outPath) {
  console.error('required: --dump --base-verifier-set --vk-sha256 --out');
  process.exit(2);
}

const dump = JSON.parse(readFileSync(path.resolve(dumpPath), 'utf8'));
const vs = JSON.parse(readFileSync(path.resolve(basePath), 'utf8'));
const roles = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal'];
const byName = Object.fromEntries(dump.filter((x) => x.name && x.lock && x.unlock).map((x) => [x.name, x]));
vs.scripts = roles.map((name) => {
  const row = byName[name];
  if (!row) throw new Error(`dump missing role ${name}`);
  return {
    lockingBytecodeHex: row.lock,
    name,
    redeemBytecodeHex: redeemFor(row.lock, row.unlock),
    sourceValueSatoshis: '1000',
  };
});
const carriers = vs.scripts.map((s) => ({
  role: s.name,
  lockingBytecode: Buffer.from(s.lockingBytecodeHex, 'hex'),
  redeemBytecode: Buffer.from(s.redeemBytecodeHex, 'hex'),
  valueSatoshis: BigInt(s.sourceValueSatoshis),
}));
const encoded = encodeCanonicalPf7CarrierSourceSet(carriers);
const sourceHash = `sha256:${createHash('sha256').update(encoded).digest('hex')}`;
vs.sourceSet = { carrierCount: 7, encoding: 'libauth-transaction-outputs-v1', sha256: sourceHash };
vs.settlementKernel = derivePf7SettlementKernelAuthority(carriers).artifact;
vs.setup = { mode: 'development-only', verificationKeySha256: vkSha.startsWith('sha256:') ? vkSha : `sha256:${vkSha}` };
vs.measurements = {
  maxUnlockingBytes: 9350,
  sourceSetSha256: sourceHash.slice('sha256:'.length),
  unlockLengthStabilize: { genesis: 7600, terminal: 9350 },
  wireBytes: vs.measurements?.wireBytes ?? 55507,
};
vs.qualification = 'development-only densFuel locks rebound to new verification key; Chipnet research only';
const serialized = JSON.stringify(vs);
parsePf7CarrierAuthority(vs); // fail closed if inconsistent
writeFileSync(path.resolve(outPath), serialized);
console.log(JSON.stringify({
  ok: true,
  out: path.resolve(outPath),
  sourceSetSha256: sourceHash,
  fileSha256: `sha256:${createHash('sha256').update(serialized).digest('hex')}`,
}, null, 2));
