// This is local Libauth BCH-2026 VM conformance evidence. All keys are
// deterministic test material and are never used outside this test process.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  createVirtualMachineBch2026,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';
import {
  finalizePreparationTransaction,
  planPreparationTransaction,
  PreparationTransactionError,
} from './preparation-transaction.mjs';

const TEST_PRIVATE_KEY = Uint8Array.from([
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 7,
]);
const OUTPOINT_WIRE = Buffer.from(
  Array.from({ length: 32 }, (_, index) => (index * 29 + 7) & 0xff),
);

function testPlan(kind, publicKey) {
  return {
    bindingCarrierBaseValueSatoshis: '1000',
    bindingLockingBytecode: '51',
    fundingOutpointIndex: '17',
    fundingOutpointTransactionHashWire: OUTPOINT_WIRE.toString('hex'),
    fundingPublicKey: Buffer.from(publicKey).toString('hex'),
    fundingSourceValueSatoshis: kind === 'deposit' ? '10200000' : '200000',
    kind,
    minimumFeeRateSatoshisPerByte: '2',
    settlementFeeFundingSatoshis: '100000',
  };
}

async function signPreparation(plan, privateKey) {
  const secp256k1 = await instantiateSecp256k1();
  const unsigned = planPreparationTransaction(plan);
  const signingSerialization = generateSigningSerializationBch({
    inputIndex: 0,
    sourceOutputs: [unsigned.sourceOutput],
    transaction: unsigned.unsignedTransaction,
  }, {
    coveredBytecode: unsigned.sourceOutput.lockingBytecode,
    signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
  });
  const signature = secp256k1.signMessageHashSchnorr(
    privateKey,
    hash256(signingSerialization),
  );
  assert.equal(typeof signature, 'object', 'test private key must be valid');
  assert.equal(signature.length, 64, 'BCH Schnorr signatures are 64 bytes');
  return {
    signed: finalizePreparationTransaction(plan, Buffer.from(signature).toString('hex')),
    unsigned,
  };
}

function hash256Node(bytes) {
  return createHash('sha256').update(
    createHash('sha256').update(bytes).digest(),
  ).digest();
}

test('Libauth BCH-2026 standard VM accepts real ALL|FORKID preparation signatures for every action', async () => {
  const secp256k1 = await instantiateSecp256k1();
  const publicKey = secp256k1.derivePublicKeyCompressed(TEST_PRIVATE_KEY);
  assert.equal(typeof publicKey, 'object');

  for (const kind of ['deposit', 'transfer', 'withdrawal']) {
    const plan = testPlan(kind, publicKey);
    const { signed } = await signPreparation(plan, TEST_PRIVATE_KEY);
    const verdict = createVirtualMachineBch2026(true).verify({
      sourceOutputs: [signed.sourceOutput],
      transaction: signed.transaction,
    });
    assert.equal(verdict, true, `${kind} preparation must pass the standard BCH-2026 VM`);
    assert.equal(signed.transaction.inputs[0].unlockingBytecode.length, 100);
    assert.equal(signed.transaction.inputs[0].unlockingBytecode[65], 0x41);
    assert.deepEqual(
      Buffer.from(signed.encodedTransaction.subarray(5, 37)),
      OUTPOINT_WIRE,
      `${kind} transaction must serialize the supplied funding outpoint in wire order`,
    );
    assert.deepEqual(
      Buffer.from(signed.transaction.inputs[0].outpointTransactionHash).reverse(),
      OUTPOINT_WIRE,
      `${kind} libauth object order must reverse exactly once before wire encoding`,
    );
    const hashWire = hash256Node(signed.encodedTransaction);
    assert.equal(signed.transactionId, Buffer.from(hashWire).reverse().toString('hex'));
    assert.equal(signed.settlementOutpoints.binding.outpointTransactionHashWire, hashWire.toString('hex'));
    assert.equal(signed.settlementOutpoints.fee.outpointTransactionHashWire, hashWire.toString('hex'));
    assert.equal(signed.settlementOutpoints.binding.outpointIndex, '0');
    assert.equal(signed.settlementOutpoints.fee.outpointIndex, '1');
    assert.equal(
      BigInt(signed.outputValues.bindingSatoshis)
        + BigInt(signed.outputValues.settlementFeeFundingSatoshis)
        + BigInt(signed.outputValues.preparationChangeSatoshis)
        + BigInt(signed.measurements.feeSatoshis),
      BigInt(plan.fundingSourceValueSatoshis),
      `${kind} preparation must account for every satoshi`,
    );
  }
});

test('real P2PKH signatures reject parent, vout, sighash, key, change, and signature mutations', async () => {
  const secp256k1 = await instantiateSecp256k1();
  const publicKey = secp256k1.derivePublicKeyCompressed(TEST_PRIVATE_KEY);
  assert.equal(typeof publicKey, 'object');
  const plan = testPlan('deposit', publicKey);
  const { signed } = await signPreparation(plan, TEST_PRIVATE_KEY);
  const vm = createVirtualMachineBch2026(true);
  const base = {
    sourceOutputs: [signed.sourceOutput],
    transaction: signed.transaction,
  };
  assert.equal(vm.verify(base), true);

  const mutations = [
    ['wrong funding parent', (transaction) => {
      transaction.inputs[0].outpointTransactionHash[0] ^= 1;
    }],
    ['wrong funding vout', (transaction) => {
      transaction.inputs[0].outpointIndex += 1;
    }],
    ['alternate sighash', (transaction) => {
      transaction.inputs[0].unlockingBytecode[65] = 0x61;
    }],
    ['public-key/source mismatch', (transaction) => {
      transaction.inputs[0].unlockingBytecode[67] ^= 1;
    }],
    ['diverted canonical change', (transaction) => {
      transaction.outputs[2].valueSatoshis -= 1n;
    }],
    ['signature mutation', (transaction) => {
      transaction.inputs[0].unlockingBytecode[1] ^= 1;
    }],
  ];
  for (const [label, mutate] of mutations) {
    const transaction = structuredClone(signed.transaction);
    mutate(transaction);
    assert.notEqual(
      vm.verify({ sourceOutputs: [signed.sourceOutput], transaction }),
      true,
      `${label} must invalidate ALL|FORKID P2PKH authorization`,
    );
  }
});

test('preparation requires an exactly dust-safe canonical change at the requested feerate', async () => {
  const secp256k1 = await instantiateSecp256k1();
  const publicKey = secp256k1.derivePublicKeyCompressed(TEST_PRIVATE_KEY);
  assert.equal(typeof publicKey, 'object');
  const plan = testPlan('transfer', publicKey);
  const initial = planPreparationTransaction(plan);
  const requiredWithoutChange = BigInt(plan.fundingSourceValueSatoshis)
    - BigInt(initial.outputValues.preparationChangeSatoshis);

  const dust = structuredClone(plan);
  dust.fundingSourceValueSatoshis = (requiredWithoutChange + 546n).toString();
  const dustSigned = await signPreparation(dust, TEST_PRIVATE_KEY);
  assert.equal(dustSigned.signed.outputValues.preparationChangeSatoshis, '546');
  assert.equal(
    dustSigned.signed.measurements.feeSatoshis,
    (BigInt(dustSigned.signed.measurements.wireBytes) * 2n).toString(),
  );

  const insufficient = structuredClone(dust);
  insufficient.fundingSourceValueSatoshis = (requiredWithoutChange + 545n).toString();
  assert.throws(
    () => planPreparationTransaction(insufficient),
    PreparationTransactionError,
  );
});
