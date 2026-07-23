// This optional integration test exercises the canonical profile-v2 hand-off
// through preparation and all ten BCH-2026 VM roles. The PF7 unlocks below
// are intentionally invalid one-byte pushes: this is structural evidence for
// roles 7..9, not a proof/PF7/G2 acceptance claim.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';
import { parsePf7CarrierAuthority } from '../core/pf7-authority.mjs';
import { generateFreshWitnessInputs } from '../fresh-witness-inputs/fresh-witness-inputs.mjs';
import {
  finalizeCompletePreparationTransaction,
  planCompletePreparationTransaction,
} from '../preparation-transaction/preparation-transaction.mjs';
import { buildSettlementTransaction } from '../settlement-transaction/settlement-transaction.mjs';
import {
  assembleCompleteG2Settlement,
  classifyCompleteG2Vm,
  planCompleteG2Settlement,
} from './g2-complete-assembler.mjs';

const bundleDirectory = process.env.SHIELD_G2_PROFILE_V2_BUNDLE;
const kinds = ['deposit', 'transfer', 'withdrawal'];
const feePrivateKey = Buffer.concat([Buffer.alloc(31), Buffer.of(7)]);
const withdrawalLockingBytecode = '51';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const transactionOutputJson = (output) => ({
  valueSatoshis: output.valueSatoshis.toString(),
  lockingBytecode: Buffer.from(output.lockingBytecode).toString('hex'),
  token: output.token === undefined ? null : {
    category: Buffer.from(output.token.category).toString('hex'),
    amount: output.token.amount.toString(),
    nft: output.token.nft === undefined ? null : {
      capability: output.token.nft.capability,
      commitment: Buffer.from(output.token.nft.commitment).toString('hex'),
    },
  },
});
const settlementBuilderInput = (complete, expectedProfile, authority) => ({
  actionPacket: Buffer.from(complete.actionPacket).toString('hex'),
  bindingCarrierBaseValueSatoshis: authority.settlementKernel.artifact.constants.bindingCarrierBaseSatoshis,
  inputs: complete.transaction.inputs.map((input) => ({
    outpointTransactionHashWire: Buffer.from(input.outpointTransactionHash).reverse().toString('hex'),
    outpointIndex: String(input.outpointIndex),
    sequenceNumber: String(input.sequenceNumber),
    unlockingBytecode: Buffer.from(input.unlockingBytecode).toString('hex'),
  })),
  instanceId: expectedProfile.instanceId.slice('sha256:'.length),
  kind: complete.kind,
  minimumFeeRateSatoshisPerByte: '1',
  outputs: complete.transaction.outputs.map(transactionOutputJson),
  profileId: expectedProfile.profileId.slice('sha256:'.length),
  sourceOutputs: complete.sourceOutputs.map(transactionOutputJson),
  stateCarrierBaseValueSatoshis: authority.settlementKernel.artifact.constants.stateCarrierBaseSatoshis,
});

async function signPreparation(input, plan) {
  const secp256k1 = await instantiateSecp256k1();
  const signingSerialization = generateSigningSerializationBch({
    inputIndex: 0,
    sourceOutputs: [plan.sourceOutput],
    transaction: plan.unsignedTransaction,
  }, {
    coveredBytecode: plan.sourceOutput.lockingBytecode,
    signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
  });
  const signature = secp256k1.signMessageHashSchnorr(
    feePrivateKey,
    hash256(signingSerialization),
  );
  assert.equal(typeof signature, 'object');
  return finalizeCompletePreparationTransaction(input, Buffer.from(signature).toString('hex'));
}

test('profile-v2 preparation hand-off constructs structurally exact ten-role settlements', async (t) => {
  if (!bundleDirectory) {
    t.skip('set SHIELD_G2_PROFILE_V2_BUNDLE to the canonical authenticated profile-v2 bundle');
    return;
  }
  const manifest = JSON.parse(await readFile(`${bundleDirectory}/manifest.json`, 'utf8'));
  const verifierSet = JSON.parse(await readFile(`${bundleDirectory}/artifacts/bch-verifier-set.json`, 'utf8'));
  const authority = parsePf7CarrierAuthority(verifierSet);
  const expectedProfile = {
    network: 'chipnet',
    profileId: manifest.identity.profileId,
    instanceId: manifest.genesis.instanceId,
  };
  const secp256k1 = await instantiateSecp256k1();
  const publicKey = secp256k1.derivePublicKeyCompressed(feePrivateKey);
  assert.equal(typeof publicKey, 'object');
  const zeroContexts = Object.freeze(Object.fromEntries(kinds.map((kind) => [kind, '00'.repeat(32)])));
  const withdrawalScriptHash = sha256(Buffer.from(withdrawalLockingBytecode, 'hex'));

  const initialWitness = await generateFreshWitnessInputs({
    bundleDirectory,
    expectedProfile,
    transactionContextDigests: zeroContexts,
    withdrawalScriptHash,
    witnessSeed: '41'.repeat(32),
  });
  const preparations = {};
  const completeInput = (kind, actionPacket, preparation) => ({
    kind,
    bundleDirectory,
    expectedProfile,
    actionPacket,
    minimumFeeRateSatoshisPerByte: 1n,
    feePrivateKey,
    feeSourceValueSatoshis: preparation.outputValues.settlementFeeFundingSatoshis,
    bindingCarrierBaseSatoshis: authority.settlementKernel.artifact.constants.bindingCarrierBaseSatoshis,
    stateCarrierBaseSatoshis: authority.settlementKernel.artifact.constants.stateCarrierBaseSatoshis,
    preparationTransactionHashWire: preparation.settlementOutpoints.binding.outpointTransactionHashWire,
    stateOutpointTransactionHashWire: 'a2'.repeat(32),
    stateOutpointIndex: 0,
    pf7: preparation.settlementOutpoints.verifierCarriers.map((carrier) => ({
      lockingBytecode: carrier.lockingBytecode,
      // Deliberately invalid PF7 material: roles 0..6 must fail in the VM.
      unlockingBytecode: '51',
      valueSatoshis: carrier.valueSatoshis,
      outpointTransactionHashWire: carrier.outpointTransactionHashWire,
      outpointIndex: Number(carrier.outpointIndex),
    })),
    ...(kind === 'withdrawal' ? { withdrawalLockingBytecode } : {}),
  });

  for (const [index, kind] of kinds.entries()) {
    const preparationInput = {
      kind,
      bundleDirectory,
      expectedProfile,
      bindingCarrierBaseValueSatoshis: authority.settlementKernel.artifact.constants.bindingCarrierBaseSatoshis,
      bindingLockingBytecode: authority.settlementKernel.bindingLock.toString('hex'),
      fundingOutpointIndex: String(index),
      fundingOutpointTransactionHashWire: Buffer.alloc(32, index + 1).toString('hex'),
      fundingPublicKey: Buffer.from(publicKey).toString('hex'),
      fundingSourceValueSatoshis: kind === 'deposit' ? '20100000' : '20100000',
      minimumFeeRateSatoshisPerByte: '1',
      settlementFeeFundingSatoshis: '100000',
    };
    const plan = await planCompletePreparationTransaction(preparationInput);
    preparations[kind] = await signPreparation(preparationInput, plan);
    assert.equal(preparations[kind].transaction.outputs.length, 10);
    assert.equal(preparations[kind].settlementOutpoints.binding.outpointIndex, '7');
    assert.equal(preparations[kind].settlementOutpoints.fee.outpointIndex, '8');
  }

  const initialPlans = Object.fromEntries(await Promise.all(kinds.map(async (kind) => [
    kind,
    await planCompleteG2Settlement(completeInput(kind, initialWitness.actions[kind].actionPacket, preparations[kind])),
  ])));
  const contexts = Object.freeze(Object.fromEntries(kinds.map((kind) => [kind, initialPlans[kind].context.digestHex])));
  const witness = await generateFreshWitnessInputs({
    bundleDirectory,
    expectedProfile,
    transactionContextDigests: contexts,
    withdrawalScriptHash,
    witnessSeed: '41'.repeat(32),
  });

  for (const kind of kinds) {
    const complete = await assembleCompleteG2Settlement(
      completeInput(kind, witness.actions[kind].actionPacket, preparations[kind]),
    );
    const canonical = buildSettlementTransaction(
      settlementBuilderInput(complete, expectedProfile, authority),
    );
    const verdict = classifyCompleteG2Vm(complete, true);
    assert.equal(canonical.transactionHex, complete.encodedTransaction.toString('hex'));
    assert.equal(complete.measurements.feeSatoshis, BigInt(complete.measurements.wireBytes));
    assert.ok(complete.measurements.wireBytes <= 59_000);
    assert.ok(complete.measurements.maximumUnlockingBytes <= 10_000);
    assert.equal(verdict.inputCount, 10);
    assert.deepEqual(verdict.failedInputIndexes, [0, 1, 2, 3, 4, 5, 6]);
  }
});
