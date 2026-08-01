import assert from 'node:assert/strict';
import test from 'node:test';

import {
  decodeTransaction,
  hash160,
  hash256,
  secp256k1,
} from '@bitauth/libauth';

import {
  parseV2RawTransaction,
} from '../../kit/v2/transaction-policy.mjs';

import {
  buildV2BetaChipnetBootstrapFunding,
  V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DEPOSIT_OUTPUTS,
  V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_SIGHASH_TYPE,
  V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_WITHDRAWAL_OUTPUTS,
  V2BetaChipnetFundingError,
} from './beta-chipnet-funding.mjs';

const SOURCE_TRANSACTION_ID =
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

function p2pkhLock(publicKey) {
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    Buffer.from(hash160(publicKey)),
    Buffer.from([0x88, 0xac]),
  ]);
}

function fixture() {
  const fundingPrivateKey = Buffer.alloc(32);
  fundingPrivateKey[31] = 7;
  const fundingPublicKey = secp256k1.derivePublicKeyCompressed(fundingPrivateKey);
  assert.ok(fundingPublicKey instanceof Uint8Array);
  const lock = p2pkhLock(fundingPublicKey);
  return {
    depositReserveSats: '10000000',
    fundingPrivateKeyHex: fundingPrivateKey.toString('hex'),
    fundingPublicKeyHex: Buffer.from(fundingPublicKey).toString('hex'),
    genesisSourceSats: '2000000',
    source: {
      lockingBytecodeHex: lock.toString('hex'),
      outputIndex: 3,
      token: null,
      transactionId: SOURCE_TRANSACTION_ID,
      valueSats: '80000000',
    },
    walletLockingBytecodeHex: lock.toString('hex'),
    withdrawalReserveSats: '1000000',
  };
}

test('builds one exact BCHN-valid bootstrap funding transaction with fixed output roles', () => {
  const input = fixture();
  const built = buildV2BetaChipnetBootstrapFunding(input);
  const decoded = decodeTransaction(Buffer.from(built.rawTransactionHex, 'hex'));
  const parsed = parseV2RawTransaction(built.rawTransactionHex);
  assert.notEqual(typeof decoded, 'string');
  assert.equal(decoded.version, 2);
  assert.equal(decoded.locktime, 0);
  assert.equal(decoded.inputs.length, 1);
  assert.equal(decoded.inputs[0].outpointIndex, 3);
  assert.equal(decoded.inputs[0].sequenceNumber, 0xffff_ffff);
  assert.equal(parsed.inputs[0].outpoint.txid, input.source.transactionId);
  assert.equal(parsed.inputs[0].outpoint.vout, input.source.outputIndex);
  assert.equal(decoded.outputs.length, 12);
  assert.equal(built.sourceOutput.outputIndex, 0);
  assert.deepEqual(
    built.actionFunding.deposits.map((entry) => entry.outputIndex),
    V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DEPOSIT_OUTPUTS,
  );
  assert.deepEqual(
    built.actionFunding.withdrawals.map((entry) => entry.outputIndex),
    V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_WITHDRAWAL_OUTPUTS,
  );
  assert.equal(built.change.outputIndex, 11);
  assert.equal(built.input.sighashType, V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_SIGHASH_TYPE);
  assert.equal(built.feeSats, String(built.serializedBytes));
  assert.equal(
    built.transactionId,
    Buffer.from(hash256(Buffer.from(built.rawTransactionHex, 'hex'))).reverse().toString('hex'),
  );
  assert.equal(JSON.stringify(built).includes(input.fundingPrivateKeyHex), false);

  const outputSum = decoded.outputs.reduce(
    (total, output) => total + output.valueSatoshis,
    0n,
  );
  assert.equal(
    BigInt(input.source.valueSats) - outputSum,
    BigInt(built.feeSats),
  );
  for (const output of decoded.outputs) {
    assert.equal(Buffer.from(output.lockingBytecode).toString('hex'), input.walletLockingBytecodeHex);
    assert.equal(output.token, undefined);
  }
});

test('is deterministic and rejects clones, tokenized sources, wrong ownership, and unsafe keys', () => {
  const input = fixture();
  const first = buildV2BetaChipnetBootstrapFunding(input);
  const second = buildV2BetaChipnetBootstrapFunding(structuredClone(input));
  assert.deepEqual(first, second);

  const cases = [
    ['unknown top-level key', (value) => { value.unknown = true; }],
    ['clone source', (value) => { value.source = { ...value.source }; value.source.extra = true; }],
    ['tokenized source', (value) => { value.source.token = { category: '00'.repeat(32) }; }],
    ['wrong source lock', (value) => { value.source.lockingBytecodeHex = '76a914' + '00'.repeat(20) + '88ac'; }],
    ['wrong public key', (value) => { value.fundingPublicKeyHex = `02${'00'.repeat(32)}`; }],
    ['unsafe private key', (value) => { value.fundingPrivateKeyHex = '00'.repeat(32); }],
    ['noncanonical amount', (value) => { value.depositReserveSats = '010000000'; }],
  ];
  for (const [label, mutate] of cases) {
    const value = structuredClone(input);
    mutate(value);
    assert.throws(
      () => buildV2BetaChipnetBootstrapFunding(value),
      (error) => error instanceof V2BetaChipnetFundingError,
      label,
    );
  }
});

test('refuses insufficient funds and dust change rather than silently reducing a reserve', () => {
  const insufficient = fixture();
  insufficient.source.valueSats = '56999999';
  assert.throws(
    () => buildV2BetaChipnetBootstrapFunding(insufficient),
    (error) => error instanceof V2BetaChipnetFundingError
      && error.code === 'BOOTSTRAP_FUNDING_INSUFFICIENT',
  );
  const dust = fixture();
  dust.source.valueSats = '57000545';
  assert.throws(
    () => buildV2BetaChipnetBootstrapFunding(dust),
    (error) => error instanceof V2BetaChipnetFundingError
      && error.code === 'BOOTSTRAP_FUNDING_INSUFFICIENT',
  );
});
