import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, unlink, writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { decodeTransaction, secp256k1 } from '@bitauth/libauth';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { CHIPNET_GENESIS_HASH, createLayer1BchnChipnetRpcForTest } from '../chipnet-rpc.mjs';
import { createV2SecretFile } from '../../profile/v2/instance-descriptor.mjs';
import { createV2ChipnetFundingWallet, deriveV2ChipnetFundingWallet } from './funding-wallet.mjs';
import {
  broadcastPreparedV2BetaOperatorFanout, buildV2BetaOperatorFanout,
  parseV2BetaOperatorFanoutInventory, prepareV2BetaOperatorFanout,
  provisionV2BetaOperatorFanoutDestinations, V2_BETA_OPERATOR_FANOUT_INVENTORY_SCHEMA,
  recoverV2BetaOperatorFanout, V2_BETA_OPERATOR_FANOUT_MINIMUM_OUTPUT_SATS,
} from './operator-fanout.mjs';
import { parseSerializedSourceOutput, parseV2RawTransaction, transactionId } from './transaction-policy.mjs';
import { inspectV2BetaOperatorSourceRegistry } from './operator-source-registry.mjs';

const H = (value) => value.toString(16).padStart(64, '0');
function rawSource(valueSats, lockingBytecodeHex, marker) { const amount = Buffer.alloc(8); amount.writeBigUInt64LE(valueSats); return Buffer.concat([Buffer.from('0200000001', 'hex'), Buffer.from(H(marker), 'hex'), Buffer.from('ffffffff00ffffffff01', 'hex'), amount, Buffer.from([25]), Buffer.from(lockingBytecodeHex, 'hex'), Buffer.from('00000000', 'hex')]).toString('hex'); }

test('canonical fanout signs two authenticated inputs into exactly 20 independently locked minimum outputs and locally verifies BCH_2026_STANDARD', () => {
  const sourceWallet = deriveV2ChipnetFundingWallet({ privateKeyHex: `${'0'.repeat(63)}1` });
  const required = V2_BETA_OPERATOR_FANOUT_MINIMUM_OUTPUT_SATS * 21n;
  const firstRaw = rawSource(required / 2n + 10_000n, sourceWallet.lockingBytecodeHex, 1);
  const secondRaw = rawSource(required - (required / 2n + 10_000n) + 10_000n, sourceWallet.lockingBytecodeHex, 2);
  const sources = [firstRaw, secondRaw].map((rawTransactionHex) => ({ rawTransactionHex, entry: { txid: parseV2RawTransaction(rawTransactionHex).txid, vout: 0, text: `${parseV2RawTransaction(rawTransactionHex).txid}:0` }, valueSats: parseV2RawTransaction(rawTransactionHex).outputs[0].valueSatoshis, lockingBytecodeHex: sourceWallet.lockingBytecodeHex }));
  const recipients = Array.from({ length: 20 }, (_, index) => deriveV2ChipnetFundingWallet({ privateKeyHex: (index + 2).toString(16).padStart(64, '0') }));
  const fanout = buildV2BetaOperatorFanout({ sourceWallet: { ...sourceWallet, signMessageHashSchnorr: (digest) => secp256k1.signMessageHashSchnorr(Buffer.from(sourceWallet.privateKeyHex, 'hex'), digest) }, authenticatedInputs: sources, recipientWallets: recipients });
  assert.equal(fanout.recipients.length, 20); assert.equal(fanout.sourceOutpoints.length, 2); assert.equal(fanout.feeSats, String(fanout.serializedBytes));
  assert.ok(fanout.recipients.every((entry) => entry.valueSats === V2_BETA_OPERATOR_FANOUT_MINIMUM_OUTPUT_SATS.toString()));
  assert.notEqual(fanout.recipients[0].lockingBytecodeHex, fanout.recipients[1].lockingBytecodeHex);
  assert.equal(createHash('sha256').update(Buffer.from(fanout.rawTransactionHex, 'hex')).digest('hex'), fanout.rawTransactionSha256);
  const decoded = decodeTransaction(Uint8Array.from(Buffer.from(fanout.rawTransactionHex, 'hex')));
  assert.notEqual(typeof decoded, 'string');
  // Libauth decodes into display order while the serialized wire bytes are the
  // reverse of BCH's display txid. This catches a detached-VM-successful
  // transaction that accidentally spends reverse(txid):vout on chain.
  assert.deepEqual(decoded.inputs.map((input) => Buffer.from(input.outpointTransactionHash).toString('hex')), fanout.sourceOutpoints.map((entry) => entry.split(':')[0]));
  assert.deepEqual(Buffer.from(fanout.rawTransactionHex, 'hex').subarray(5, 37), Buffer.from(fanout.sourceOutpoints[0].split(':')[0], 'hex').reverse());
});

test('inventory is canonical, unique, and requires multi-input source authority', () => {
  const a = `${H(1)}:0`; const b = `${H(2)}:1`;
  assert.equal(parseV2BetaOperatorFanoutInventory(Buffer.from(canonicalizeJcs({ schema: V2_BETA_OPERATOR_FANOUT_INVENTORY_SCHEMA, sourceOutpoints: [b, a] }))).sources[0].text, a);
  assert.throws(() => parseV2BetaOperatorFanoutInventory(Buffer.from(canonicalizeJcs({ schema: V2_BETA_OPERATOR_FANOUT_INVENTORY_SCHEMA, sourceOutpoints: [a] }))), { code: 'OPERATOR_FANOUT_INVALID' });
  assert.throws(() => parseV2BetaOperatorFanoutInventory(Buffer.from(`${canonicalizeJcs({ schema: V2_BETA_OPERATOR_FANOUT_INVENTORY_SCHEMA, sourceOutpoints: [a, b] })}\n`)), { code: 'OPERATOR_FANOUT_INVALID' });
});

test('production fanout defaults to pinned public TLS while accepting direct BCHN only as an injected lab seam', async () => {
  const source = await readFile(new URL('./operator-fanout.mjs', import.meta.url), 'utf8');
  assert.match(source, /rpc \?\? await createPublicChipnetFulcrumRpc\(\)/u);
  assert.doesNotMatch(source, /rpc \?\? await createLayer1BchnChipnetRpc\(\)/u);
  assert.match(source, /assertLayer1BchnChipnetRpc\(value\)/u);
  assert.match(source, /if \(ownsRpc\) \{ try \{ await capability\.close\?\.\(\); \} catch \{\} \}/u);
});

test('operator provisioner safely resumes a partial crash without replacing established destination keys', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-fanout-provision-')); await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const first = await provisionV2BetaOperatorFanoutDestinations({ operatorRoot: root });
  assert.equal(first.recipientCount, 21); assert.equal(new Set(first.wallets.map((wallet) => wallet.lockingBytecodeHex)).size, 21);
  // Model a crash after the first twenty exclusive writes, before wallet 21.
  await unlink(path.join(root, 'fanout-wallets', 'wallet-21.json'));
  const resumed = await provisionV2BetaOperatorFanoutDestinations({ operatorRoot: root });
  assert.deepEqual(resumed.wallets.slice(0, 20), first.wallets.slice(0, 20));
  assert.equal(resumed.wallets.length, 21);
  assert.notEqual(resumed.wallets[20].lockingBytecodeHex, first.wallets[20].lockingBytecodeHex);
});

test('operator provisioner rejects a directory symlink without chmod-following its target', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-fanout-symlink-'));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const victim = path.join(root, 'victim');
  await mkdir(victim, { mode: 0o755 });
  await chmod(victim, 0o755);
  await symlink(victim, path.join(root, 'fanout-wallets'), 'dir');
  await assert.rejects(
    () => provisionV2BetaOperatorFanoutDestinations({ operatorRoot: root }),
    { code: 'OPERATOR_FANOUT_PATH_REJECTED' },
  );
  assert.equal((await lstat(victim)).mode & 0o777, 0o755);
});

test('fanout source wallet and inventory reject a symlinked parent before opening a network capability', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-fanout-input-alias-')); await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const sourceWalletPath = path.join(root, 'source-wallet.json'); await createV2ChipnetFundingWallet({ filename: sourceWalletPath });
  const inventoryPath = path.join(root, 'inventory.json');
  await createV2SecretFile(inventoryPath, Buffer.from(canonicalizeJcs({ schema: V2_BETA_OPERATOR_FANOUT_INVENTORY_SCHEMA, sourceOutpoints: [`${H(1)}:0`, `${H(2)}:0`] }), 'utf8'));
  const alias = path.join(root, 'alias'); await symlink(root, alias, 'dir');
  await assert.rejects(
    () => prepareV2BetaOperatorFanout({ operatorRoot: root, runId: 'alias-wallet-r1', sourceWalletPath: path.join(alias, 'source-wallet.json'), inventoryPath }),
    { code: 'OPERATOR_FANOUT_PATH_REJECTED' },
  );
  await assert.rejects(
    () => prepareV2BetaOperatorFanout({ operatorRoot: root, runId: 'alias-inventory-r1', sourceWalletPath, inventoryPath: path.join(alias, 'inventory.json') }),
    { code: 'OPERATOR_FANOUT_PATH_REJECTED' },
  );
});

function live(lockingBytecodeHex, valueSats) { return { scriptPubKey: { hex: lockingBytecodeHex }, valueSatoshis: valueSats.toString() }; }

async function fakeBchnForFanout({ sourceTransactions, hideFanoutReadback = false }) {
  const rawByTxid = new Map(sourceTransactions.map(({ rawTransactionHex }) => [parseV2RawTransaction(rawTransactionHex).txid, rawTransactionHex]));
  const unspent = new Map(sourceTransactions.map(({ rawTransactionHex, lockingBytecodeHex, valueSats }) => [`${parseV2RawTransaction(rawTransactionHex).txid}:0`, live(lockingBytecodeHex, valueSats)]));
  let sends = 0; let rejectMempool = false;
  const rpc = await createLayer1BchnChipnetRpcForTest({ executeLayer1Cli: async (method, args) => {
    if (method === 'getblockhash') return CHIPNET_GENESIS_HASH;
    if (method === 'testmempoolaccept') return JSON.stringify(rejectMempool
      ? [{ allowed: false, txid: transactionId(Buffer.from(args[0], 'hex')), 'reject-reason': 'test rejection' }]
      : [{ allowed: true, txid: transactionId(Buffer.from(args[0], 'hex')) }]);
    if (method === 'sendrawtransaction') {
      const rawTransactionHex = args[0]; const parsed = parseV2RawTransaction(rawTransactionHex); sends += 1; rawByTxid.set(parsed.txid, rawTransactionHex);
      parsed.outputs.forEach((output, index) => {
        const sourceOutput = parseSerializedSourceOutput(output.serializedHex);
        unspent.set(`${parsed.txid}:${index}`, live(sourceOutput.lockingBytecodeHex, sourceOutput.valueSatoshis));
      });
      return parsed.txid;
    }
    if (method === 'getrawtransaction') {
      const rawTransactionHex = rawByTxid.get(args[0]);
      if (rawTransactionHex === undefined) throw new Error('missing test transaction');
      return args[1] === true ? JSON.stringify({ txid: args[0], hex: rawTransactionHex }) : rawTransactionHex;
    }
    if (method === 'gettxout') {
      if (hideFanoutReadback && sends > 0 && !sourceTransactions.some(({ rawTransactionHex }) => parseV2RawTransaction(rawTransactionHex).txid === args[0])) return JSON.stringify(null);
      return JSON.stringify(unspent.get(`${args[0]}:${args[1]}`) ?? null);
    }
    throw new Error(`unexpected test BCHN method ${method}`);
  } });
  return { rpc, sends: () => sends, setRejectMempool: (value) => { rejectMempool = Boolean(value); }, unspent };
}

test('fanout admits exactly one send, recovery is read-only, and a pre-send rejection remains prepared', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-fanout-recovery-')); await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  await provisionV2BetaOperatorFanoutDestinations({ operatorRoot: root });
  const sourceWalletPath = path.join(root, 'source-wallet.json'); const sourceWallet = await createV2ChipnetFundingWallet({ filename: sourceWalletPath });
  const required = V2_BETA_OPERATOR_FANOUT_MINIMUM_OUTPUT_SATS * 21n;
  const sourceTransactions = [
    { rawTransactionHex: rawSource(required / 2n + 10_000n, sourceWallet.lockingBytecodeHex, 1001), lockingBytecodeHex: sourceWallet.lockingBytecodeHex, valueSats: required / 2n + 10_000n },
    { rawTransactionHex: rawSource(required - (required / 2n + 10_000n) + 10_000n, sourceWallet.lockingBytecodeHex, 1002), lockingBytecodeHex: sourceWallet.lockingBytecodeHex, valueSats: required - (required / 2n + 10_000n) + 10_000n },
  ];
  const inventoryPath = path.join(root, 'inventory.json');
  await createV2SecretFile(inventoryPath, Buffer.from(canonicalizeJcs({ schema: V2_BETA_OPERATOR_FANOUT_INVENTORY_SCHEMA, sourceOutpoints: sourceTransactions.map(({ rawTransactionHex }) => `${parseV2RawTransaction(rawTransactionHex).txid}:0`) }), 'utf8'));
  const fake = await fakeBchnForFanout({ sourceTransactions });
  const prepared = await prepareV2BetaOperatorFanout({ operatorRoot: root, runId: 'fanout-recovery-r1', sourceWalletPath, inventoryPath }, { rpc: fake.rpc });
  assert.equal(prepared.recipientCount, 20);
  await assert.rejects(() => recoverV2BetaOperatorFanout({ operatorRoot: root, runId: 'fanout-recovery-r1' }, { rpc: fake.rpc }), { code: 'OPERATOR_FANOUT_RECOVERY_REJECTED' });
  fake.setRejectMempool(true);
  await assert.rejects(() => broadcastPreparedV2BetaOperatorFanout({ operatorRoot: root, runId: 'fanout-recovery-r1' }, { rpc: fake.rpc }), { code: 'OPERATOR_FANOUT_SEND_REJECTED' });
  assert.equal(inspectV2BetaOperatorSourceRegistry({ operatorRoot: root }).fanoutOperations[0].state, 'prepared');
  assert.equal(fake.sends(), 0);
  fake.setRejectMempool(false);
  const sent = await broadcastPreparedV2BetaOperatorFanout({ operatorRoot: root, runId: 'fanout-recovery-r1' }, { rpc: fake.rpc });
  assert.equal(sent.status, 'accepted-zero-conf'); assert.equal(fake.sends(), 1);
  const recovered = await recoverV2BetaOperatorFanout({ operatorRoot: root, runId: 'fanout-recovery-r1' }, { rpc: fake.rpc });
  assert.equal(recovered.status, 'reconciled-zero-conf'); assert.equal(fake.sends(), 1);
  const view = inspectV2BetaOperatorSourceRegistry({ operatorRoot: root });
  assert.equal(view.fanoutOperations[0].state, 'reconciled'); assert.equal(view.sourceCount, 20);

  const journalPath = path.join(root, 'fanout-runs', 'fanout-recovery-r1', 'fanout-journal.json');
  const journal = JSON.parse(await readFile(journalPath, 'utf8')); journal.feeSats = '0';
  await writeFile(journalPath, canonicalizeJcs(journal), { mode: 0o600 });
  await assert.rejects(() => recoverV2BetaOperatorFanout({ operatorRoot: root, runId: 'fanout-recovery-r1' }, { rpc: fake.rpc }), { code: 'OPERATOR_FANOUT_RECOVERY_REJECTED' });
});

test('fanout readback failure after a successful send is durably indeterminate and recovery never resends', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-fanout-indeterminate-')); await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  await provisionV2BetaOperatorFanoutDestinations({ operatorRoot: root });
  const sourceWalletPath = path.join(root, 'source-wallet.json'); const sourceWallet = await createV2ChipnetFundingWallet({ filename: sourceWalletPath });
  const required = V2_BETA_OPERATOR_FANOUT_MINIMUM_OUTPUT_SATS * 21n;
  const sourceTransactions = [
    { rawTransactionHex: rawSource(required / 2n + 10_000n, sourceWallet.lockingBytecodeHex, 2001), lockingBytecodeHex: sourceWallet.lockingBytecodeHex, valueSats: required / 2n + 10_000n },
    { rawTransactionHex: rawSource(required - (required / 2n + 10_000n) + 10_000n, sourceWallet.lockingBytecodeHex, 2002), lockingBytecodeHex: sourceWallet.lockingBytecodeHex, valueSats: required - (required / 2n + 10_000n) + 10_000n },
  ];
  const inventoryPath = path.join(root, 'inventory.json');
  await createV2SecretFile(inventoryPath, Buffer.from(canonicalizeJcs({ schema: V2_BETA_OPERATOR_FANOUT_INVENTORY_SCHEMA, sourceOutpoints: sourceTransactions.map(({ rawTransactionHex }) => `${parseV2RawTransaction(rawTransactionHex).txid}:0`) }), 'utf8'));
  const fake = await fakeBchnForFanout({ sourceTransactions, hideFanoutReadback: true });
  await prepareV2BetaOperatorFanout({ operatorRoot: root, runId: 'fanout-indeterminate-r1', sourceWalletPath, inventoryPath }, { rpc: fake.rpc });
  await assert.rejects(() => broadcastPreparedV2BetaOperatorFanout({ operatorRoot: root, runId: 'fanout-indeterminate-r1' }, { rpc: fake.rpc }), { code: 'OPERATOR_FANOUT_SEND_INDETERMINATE' });
  const view = inspectV2BetaOperatorSourceRegistry({ operatorRoot: root });
  assert.equal(view.fanoutOperations[0].state, 'indeterminate');
  assert.equal(view.fanoutInputReservations.every((entry) => entry.state === 'indeterminate'), true);
  const recovered = await recoverV2BetaOperatorFanout({ operatorRoot: root, runId: 'fanout-indeterminate-r1' }, { rpc: fake.rpc });
  assert.equal(recovered.status, 'not-observed-zero-conf');
  assert.equal(fake.sends(), 1);
});
