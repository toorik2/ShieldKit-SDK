/**
 * Tip lifecycle skeleton — state@0 packet path green; combined FRI offset documented.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import {
  createVirtualMachineBch2026,
  hexToBin,
  binToHex,
  hash256,
  encodeLockingBytecodeP2sh32,
} from '@bitauth/libauth';
import {
  buildTipGenesisLocal,
  buildActionPacket,
  buildStateUnlock,
  describeTipActionSpend,
  ROLE_INPUT_BASE,
} from './tip-lifecycle.mjs';
import { buildStateScriptSig } from './state-covenant.mjs';
import { KIND } from '../core/codecs/packet.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const ASSEMBLY = path.join(ROOT, 'evidence/production/assemble-fixed/assemble-transfer-d4-b32.json');
const vm = createVirtualMachineBch2026();

function evalStateOnly({ covenant, packetHex, preHex, postHex, categoryHex, roleLocks }) {
  const n = roleLocks.length;
  const stateLock = covenant.lockingHex;
  const z32 = new Uint8Array(32);
  const preRes = Buffer.from(preHex, 'hex').readBigUInt64LE(112);
  const postRes = Buffer.from(postHex, 'hex').readBigUInt64LE(112);
  const base = 2000n;
  const inputs = [
    {
      outpointTransactionHash: z32,
      outpointIndex: 0,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: hexToBin(buildStateScriptSig(covenant.redeemHex, packetHex)),
    },
  ];
  for (let i = 0; i < n; i += 1) {
    inputs.push({
      outpointTransactionHash: z32,
      outpointIndex: i + 1,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: hexToBin('51'),
    });
  }
  const outputs = [
    {
      lockingBytecode: hexToBin(stateLock),
      valueSatoshis: base + postRes,
      token: {
        category: hexToBin(categoryHex),
        amount: 0n,
        nft: { capability: 'mutable', commitment: hexToBin(postHex) },
      },
    },
  ];
  for (let i = 0; i < n; i += 1) {
    outputs.push({ lockingBytecode: hexToBin(roleLocks[i]), valueSatoshis: 1000n });
  }
  const sourceOutputs = [
    {
      lockingBytecode: hexToBin(stateLock),
      valueSatoshis: base + preRes,
      token: {
        category: hexToBin(categoryHex),
        amount: 0n,
        nft: { capability: 'mutable', commitment: hexToBin(preHex) },
      },
    },
  ];
  for (let i = 0; i < n; i += 1) {
    sourceOutputs.push({ lockingBytecode: hexToBin(roleLocks[i]), valueSatoshis: 1000n });
  }
  const tr = vm.debug({
    inputIndex: 0,
    sourceOutputs,
    transaction: { version: 2, inputs, outputs, locktime: 0 },
  });
  const last = tr[tr.length - 1];
  const top = last.stack?.length ? last.stack[last.stack.length - 1] : undefined;
  const ok =
    !last.error && top && top.length > 0 && !(top.length === 1 && top[0] === 0);
  return { ok, error: last.error ? String(last.error).slice(0, 200) : null };
}

test('tip genesis local has state@0 covenant not operator key', () => {
  const tip = buildTipGenesisLocal();
  assert.equal(tip.covenant.operatorKeySpendable, false);
  assert.equal(tip.covenant.bindsSfc1, true);
  assert.equal(tip.topology.stateIndex, 0);
  assert.equal(tip.topology.roleBase, ROLE_INPUT_BASE);
  assert.equal(tip.stateBytes.length, 128);
});

test('deposit action packet + state unlock Libauth accepts on tip shape', () => {
  const tip = buildTipGenesisLocal();
  const categoryHex = 'ab'.repeat(32);
  const action = buildActionPacket({
    kind: KIND.DEPOSIT,
    preState: tip.state,
    categoryHex,
  });
  const unlock = buildStateUnlock({ covenant: tip.covenant, packetHex: action.packetHex });
  assert.ok(unlock.unlockingHex.length > 100);
  const roleLocks = Array.from({ length: 19 }, (_, i) => {
    const redeem = Buffer.concat([Buffer.from([0x51]), Buffer.from(`role${i}`)]);
    const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
    return binToHex(locking);
  });
  const r = evalStateOnly({
    covenant: tip.covenant,
    packetHex: action.packetHex,
    preHex: action.preHex,
    postHex: action.postHex,
    categoryHex,
    roleLocks,
  });
  assert.equal(r.ok, true, r.error);
});

test('describeTipActionSpend reports combined FRI ready for roleBase=1 assembly', () => {
  const base1 = path.join(
    ROOT,
    'evidence/production/assemble-state0/assemble-transfer-d4-b32-base1.materialized.json',
  );
  const d = describeTipActionSpend({
    assemblyPath: existsSync(base1) ? base1 : existsSync(ASSEMBLY) ? ASSEMBLY : null,
    kind: KIND.DEPOSIT,
  });
  assert.equal(d.ok, true);
  assert.equal(d.topology.roleBase, 1);
  assert.equal(d.state.operatorKeySpendable, false);
  if (existsSync(base1)) {
    assert.equal(d.combinedFriAllAcceptReady, true);
    assert.equal(d.blockers.length, 0);
  }
});
