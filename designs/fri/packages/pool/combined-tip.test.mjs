/**
 * Combined tip Libauth: state@0 + FRI roles@1..19 (roleIndexBase=1).
 * Drives shipped assemble artifacts + compileStateCovenant + SFP1 packet unlock.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createVirtualMachineBch2026,
  hexToBin,
  binToHex,
  encodeTransaction,
} from '@bitauth/libauth';
import {
  compileStateCovenant,
  buildStateScriptSig,
  DENOMINATION_SATS,
  ROLE_COUNT,
} from './state-covenant.mjs';
import { buildActionPacket, ROLE_INPUT_BASE } from './tip-lifecycle.mjs';
import { createPoolLocal } from './create-pool.mjs';
import { KIND } from '../core/codecs/packet.mjs';
import { materializeAssembly } from '../settlement/settlement.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const EVID = path.join(ROOT, 'evidence/production/assemble-state0');
const OUT = path.join(ROOT, 'evidence/production');
const vm = createVirtualMachineBch2026();

function loadMat(kind) {
  const p = path.join(EVID, `assemble-${kind}-d4-b32-base1.materialized.json`);
  if (!existsSync(p)) {
    const raw = path.join(EVID, `assemble-${kind}-d4-b32-base1.json`);
    if (!existsSync(raw)) throw new Error(`missing ${raw}`);
    return materializeAssembly(JSON.parse(readFileSync(raw, 'utf8')));
  }
  return JSON.parse(readFileSync(p, 'utf8'));
}

function evalCombined({ kind = 'deposit' } = {}) {
  const mat = loadMat(kind);
  assert.equal(mat.inputBase ?? mat.roleIndexBase, 1);
  assert.equal(mat.vm?.allAccept, true);
  assert.equal(mat.roleHex?.length, ROLE_COUNT);

  const roleLocks = mat.roleHex.map((r) => r.lockingHex);
  const covenant = compileStateCovenant({
    roleCount: ROLE_COUNT,
    networkId: 2,
    bindSfc1: true,
  });
  const tip = createPoolLocal({ network: 'chipnet' });
  const categoryHex = createHash('sha256')
    .update(`combined-tip-${kind}-${tip.profileId}`)
    .digest('hex');

  const kindCode =
    kind === 'deposit' ? KIND.DEPOSIT : kind === 'withdrawal' ? KIND.WITHDRAWAL : KIND.TRANSFER;
  // Transfer/withdraw need live notes — seed via deposit transition first when needed.
  let preState = tip.state;
  if (kindCode !== KIND.DEPOSIT) {
    const seeded = buildActionPacket({
      kind: KIND.DEPOSIT,
      preState: tip.state,
      categoryHex,
    });
    preState = seeded.postState;
  }
  const action = buildActionPacket({
    kind: kindCode,
    preState,
    categoryHex,
  });
  const stateUnlockHex = buildStateScriptSig(covenant.redeemHex, action.packetHex);

  const preRes = Buffer.from(action.preHex, 'hex').readBigUInt64LE(112);
  const postRes = Buffer.from(action.postHex, 'hex').readBigUInt64LE(112);
  const base = 2000n;
  const vin = base + preRes;
  const vout = base + postRes;
  const z32 = new Uint8Array(32);

  // Tip shape: vin0 state + vin1..19 FRI roles
  const inputs = [
    {
      outpointTransactionHash: z32,
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: hexToBin(stateUnlockHex),
    },
  ];
  for (let i = 0; i < ROLE_COUNT; i += 1) {
    inputs.push({
      outpointTransactionHash: z32,
      outpointIndex: i + 1,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: hexToBin(mat.roleHex[i].scriptSigHex),
    });
  }

  const outputs = [
    {
      lockingBytecode: hexToBin(covenant.lockingHex),
      valueSatoshis: vout,
      token: {
        category: hexToBin(categoryHex),
        amount: 0n,
        nft: { capability: 'mutable', commitment: hexToBin(action.postHex) },
      },
    },
  ];
  for (let i = 0; i < ROLE_COUNT; i += 1) {
    outputs.push({
      lockingBytecode: hexToBin(roleLocks[i]),
      valueSatoshis: 1000n,
    });
  }

  const sourceOutputs = [
    {
      lockingBytecode: hexToBin(covenant.lockingHex),
      valueSatoshis: vin,
      token: {
        category: hexToBin(categoryHex),
        amount: 0n,
        nft: { capability: 'mutable', commitment: hexToBin(action.preHex) },
      },
    },
  ];
  for (let i = 0; i < ROLE_COUNT; i += 1) {
    sourceOutputs.push({
      lockingBytecode: hexToBin(roleLocks[i]),
      valueSatoshis: 1000n,
    });
  }

  const transaction = { version: 2, inputs, outputs, locktime: 0 };
  const perInput = [];
  for (let i = 0; i < inputs.length; i += 1) {
    const tr = vm.debug({ inputIndex: i, sourceOutputs, transaction });
    const last = tr[tr.length - 1];
    const top = last.stack?.length ? last.stack[last.stack.length - 1] : undefined;
    const ok =
      !last.error &&
      top &&
      top.length > 0 &&
      !(top.length === 1 && top[0] === 0);
    perInput.push({
      idx: i,
      role: i === 0 ? 'state' : mat.roleHex[i - 1].role,
      ok,
      error: last.error ? String(last.error).slice(0, 180) : null,
      unlockBytes: inputs[i].unlockingBytecode.length,
    });
  }
  const nOk = perInput.filter((p) => p.ok).length;
  let txBytes = null;
  try {
    const enc = encodeTransaction(transaction);
    if (typeof enc !== 'string') txBytes = enc.length;
  } catch {
    /* optional size */
  }
  return {
    kind,
    allAccept: nOk === perInput.length,
    nOk,
    nInputs: perInput.length,
    roleIndexBase: ROLE_INPUT_BASE,
    stateRedeemBytes: covenant.redeemBytes,
    stateUnlockBytes: stateUnlockHex.length / 2,
    maxUnlockBytes: Math.max(...perInput.map((p) => p.unlockBytes)),
    txBytes,
    denominationSats: DENOMINATION_SATS,
    categoryHex,
    statementDigest: action.statementDigest,
    lockSetSha256: createHash('sha256')
      .update(roleLocks.join('|'))
      .digest('hex'),
    perInput,
    fails: perInput.filter((p) => !p.ok),
  };
}

test('combined tip deposit: state@0 + FRI roles Libauth allAccept', () => {
  const r = evalCombined({ kind: 'deposit' });
  assert.equal(r.nInputs, 20);
  assert.equal(r.roleIndexBase, 1);
  assert.equal(r.allAccept, true, JSON.stringify(r.fails, null, 2));
  assert.ok(r.maxUnlockBytes <= 10_000, `maxUnlock ${r.maxUnlockBytes}`);
  if (r.txBytes != null) {
    assert.ok(r.txBytes <= 100_000, `txBytes ${r.txBytes}`);
  }
  mkdirSync(OUT, { recursive: true });
  writeFileSync(
    path.join(OUT, 'COMBINED_TIP_DEPOSIT.json'),
    JSON.stringify({ schema: 'shieldkit-fri-combined-tip-v1', ...r, timestamp: new Date().toISOString() }, null, 2) +
      '\n',
  );
});

test('combined tip transfer: state@0 + FRI roles Libauth allAccept', () => {
  const r = evalCombined({ kind: 'transfer' });
  assert.equal(r.allAccept, true, JSON.stringify(r.fails, null, 2));
  writeFileSync(
    path.join(OUT, 'COMBINED_TIP_TRANSFER.json'),
    JSON.stringify({ schema: 'shieldkit-fri-combined-tip-v1', ...r, timestamp: new Date().toISOString() }, null, 2) +
      '\n',
  );
});

test('combined tip withdrawal: state@0 + FRI roles Libauth allAccept', () => {
  const r = evalCombined({ kind: 'withdrawal' });
  assert.equal(r.allAccept, true, JSON.stringify(r.fails, null, 2));
  writeFileSync(
    path.join(OUT, 'COMBINED_TIP_WITHDRAWAL.json'),
    JSON.stringify({ schema: 'shieldkit-fri-combined-tip-v1', ...r, timestamp: new Date().toISOString() }, null, 2) +
      '\n',
  );
});
