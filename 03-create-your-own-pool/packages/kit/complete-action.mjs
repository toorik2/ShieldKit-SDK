/**
 * One-shot action spine: prep → SCCT plan → prove → unlocks → assemble.
 * Desktop/Node only (snarkjs + unlock-builder). Fee key policy A.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import {
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
} from '../action/node_modules/@bitauth/libauth/build/index.js';
import {
  planCompletePreparationTransaction,
  finalizeCompletePreparationTransaction,
} from '../action/prep.mjs';
import { generateFreshWitnessInputs } from '../action/witness.mjs';
import {
  planCompleteSettlement,
  assembleCompleteSettlement,
  classifyCompleteSettlementVm,
} from '../action/assemble.mjs';
import { parsePf7CarrierAuthority } from '../prove/authority.mjs';
import { adaptSnarkjsGroth16 } from '../prove/groth16.mjs';
import { buildVerifierUnlocks, PIN_LENS } from '../unlock-builder/index.mjs';

const require = createRequire(import.meta.url);

function fail(code, message) {
  const err = new Error(message);
  err.code = code;
  throw err;
}

const sha256File = async (p) => createHash('sha256').update(await readFile(p)).digest('hex');

function loadVerifierAuthority(bundleDirectory) {
  const candidates = [
    path.join(bundleDirectory, 'artifacts/verifier-set.bin'),
    path.join(bundleDirectory, 'artifacts/bch-verifier-set.json'),
    path.join(bundleDirectory, 'artifacts/verifier-set.json'),
  ];
  for (const p of candidates) {
    if (!existsSync(p)) continue;
    const vs = JSON.parse(readFileSync(p, 'utf8'));
    return parsePf7CarrierAuthority(vs);
  }
  fail('VS', `bch-verifier-set not found under ${bundleDirectory}/artifacts`);
}

function resolveProveArtifacts(bundleDirectory) {
  const wasm = [
    path.join(bundleDirectory, 'artifacts/g1_relation.wasm'),
    path.join(bundleDirectory, 'artifacts/witness-generator.wasm'),
    path.join(bundleDirectory, 'artifacts/circuit.wasm'),
  ].find((p) => existsSync(p));
  const zkey = [
    path.join(bundleDirectory, 'artifacts/final.zkey'),
    path.join(bundleDirectory, 'artifacts/proving-key.zkey'),
    path.join(bundleDirectory, 'artifacts/circuit_final.zkey'),
  ].find((p) => existsSync(p));
  const vk = [
    path.join(bundleDirectory, 'artifacts/verification_key.json'),
    path.join(bundleDirectory, 'artifacts/verification-key.json'),
    path.join(bundleDirectory, 'artifacts/vk.json'),
  ].find((p) => existsSync(p));
  if (!wasm || !zkey || !vk) {
    fail('PROVE_ARTIFACTS', `missing wasm/zkey/vk under ${bundleDirectory}/artifacts`);
  }
  return { wasm, zkey, vk };
}

/**
 * @param {object} input see plan / README
 */
export async function completeAction(input) {
  const kind = input.kind;
  if (!['deposit', 'transfer', 'withdrawal'].includes(kind)) fail('KIND', `unsupported kind ${kind}`);
  const bundleDirectory = path.resolve(input.bundleDirectory);
  const workDir = path.resolve(input.workDir);
  await mkdir(workDir, { recursive: true });

  const expectedProfile = input.expectedProfile;
  if (!expectedProfile?.profileId || !expectedProfile?.instanceId) {
    fail('PROFILE', 'expectedProfile.{profileId,instanceId} required');
  }

  const authority = loadVerifierAuthority(bundleDirectory);
  const bindingBase = BigInt(
    input.bindingCarrierBase
    ?? authority.settlementKernel.artifact?.constants?.bindingCarrierBaseSatoshis
    ?? 1000,
  );
  const stateBase = BigInt(
    input.stateCarrierBase
    ?? authority.settlementKernel.artifact?.constants?.stateCarrierBaseSatoshis
    ?? 1080,
  );
  const feeFunding = String(input.settlementFeeFundingSatoshis ?? '100000');
  const feePrivateKey = Buffer.from(input.feePrivateKey);
  if (feePrivateKey.length !== 32) fail('FEE_KEY', 'feePrivateKey must be 32 bytes');

  const bindingLock = Buffer.from(authority.settlementKernel.bindingLock).toString('hex');
  const funding = input.funding;
  const prepIn = {
    kind,
    bundleDirectory,
    expectedProfile,
    bindingCarrierBaseValueSatoshis: bindingBase.toString(),
    bindingLockingBytecode: bindingLock,
    fundingOutpointIndex: String(funding.vout),
    fundingOutpointTransactionHashWire: Buffer.from(funding.txid, 'hex').reverse().toString('hex'),
    fundingPublicKey: funding.publicKeyHex,
    fundingSourceValueSatoshis: String(funding.sats),
    minimumFeeRateSatoshisPerByte: '1',
    settlementFeeFundingSatoshis: feeFunding,
  };

  const secp = await instantiateSecp256k1();
  const prepPlan = await planCompletePreparationTransaction(prepIn);
  const ss = generateSigningSerializationBch({
    inputIndex: 0,
    sourceOutputs: [prepPlan.sourceOutput],
    transaction: prepPlan.unsignedTransaction,
  }, {
    coveredBytecode: prepPlan.sourceOutput.lockingBytecode,
    signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
  });
  const sig = secp.signMessageHashSchnorr(feePrivateKey, hash256(ss));
  if (typeof sig === 'string') fail('SIGN', sig);
  const prep = await finalizeCompletePreparationTransaction(prepIn, Buffer.from(sig).toString('hex'));
  const prepHex = Buffer.from(encodeTransaction(prep.transaction)).toString('hex');
  const prepTxid = Buffer.from(hash256(Buffer.from(prepHex, 'hex'))).reverse().toString('hex');

  const digests = {
    deposit: '00'.repeat(32),
    transfer: '00'.repeat(32),
    withdrawal: '00'.repeat(32),
    ...(input.digests || {}),
    [kind]: '00'.repeat(32),
  };

  const templateUnlocks = input.stabilizeUnlockTemplate;
  const planPf7 = (preparation) => preparation.settlementOutpoints.verifierCarriers.map((carrier, i) => {
    let unlockHex;
    if (templateUnlocks?.[i]?.unlock) unlockHex = templateUnlocks[i].unlock;
    else if (templateUnlocks?.[i]?.unlockHex) unlockHex = templateUnlocks[i].unlockHex;
    else unlockHex = '00'.repeat(PIN_LENS[i]);
    return {
      lockingBytecode: carrier.lockingBytecode,
      unlockingBytecode: unlockHex,
      valueSatoshis: carrier.valueSatoshis,
      outpointTransactionHashWire: carrier.outpointTransactionHashWire,
      outpointIndex: Number(carrier.outpointIndex),
    };
  });

  const transferHops = input.transferHops ?? 1;
  const priorCycles = input.priorCycles || [];
  const priorOpenNotes = input.priorOpenNotes || [];
  const tipForest = input.tipForest || null;
  // Multi-note stack: openNotes and/or tipForest (required after any withdraw residual).
  const stackMode = priorOpenNotes.length > 0 || !!tipForest || input.actionKind != null;
  const witnessCommon = {
    bundleDirectory,
    expectedProfile,
    withdrawalScriptHash: input.withdrawalScriptHash,
    witnessSeed: input.witnessSeed,
    priorCycles,
    ...(tipForest ? { tipForest } : {}),
    ...(stackMode
      ? { priorOpenNotes, actionKind: input.actionKind || kind, transferHops: 0 }
      : { transferHops }),
  };
  const w0 = await generateFreshWitnessInputs({
    ...witnessCommon,
    transactionContextDigests: digests,
  });
  if (!w0.actions[kind]) fail('WITNESS', `witness missing action for ${kind}`);

  const planInput0 = {
    kind,
    bundleDirectory,
    expectedProfile,
    actionPacket: w0.actions[kind].actionPacket,
    minimumFeeRateSatoshisPerByte: 1n,
    feePrivateKey,
    feeSourceValueSatoshis: prep.outputValues.settlementFeeFundingSatoshis,
    bindingCarrierBaseSatoshis: bindingBase,
    stateCarrierBaseSatoshis: stateBase,
    preparationTransactionHashWire: prep.settlementOutpoints.binding.outpointTransactionHashWire,
    stateOutpointTransactionHashWire: Buffer.from(input.stateTxid, 'hex').reverse().toString('hex'),
    stateOutpointIndex: input.stateOutpointIndex ?? 0,
    pf7: planPf7(prep),
    ...(kind === 'withdrawal' ? { withdrawalLockingBytecode: input.withdrawalLockingBytecode } : {}),
  };
  const plan0 = await planCompleteSettlement(planInput0);
  const digests1 = { ...digests, [kind]: plan0.context.digestHex };
  const w1 = await generateFreshWitnessInputs({
    ...witnessCommon,
    transactionContextDigests: digests1,
  });
  const plan1 = await planCompleteSettlement({
    ...planInput0,
    actionPacket: w1.actions[kind].actionPacket,
  });
  if (plan1.context.digestHex !== plan0.context.digestHex) {
    fail('SCCT', `${kind} SCCT digest drift`);
  }

  const packetPath = path.join(workDir, `${kind}.packet`);
  await writeFile(packetPath, Buffer.from(w1.actions[kind].actionPacket));
  await writeFile(path.join(workDir, `${kind}.circuitInput.json`), JSON.stringify(w1.actions[kind].circuitInput));

  const { wasm, zkey, vk: vkPath } = resolveProveArtifacts(bundleDirectory);
  const snarkjs = require('../profile/node_modules/snarkjs');
  const proveT0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    w1.actions[kind].circuitInput,
    wasm,
    zkey,
  );
  const proveMs = Date.now() - proveT0;
  const vk = JSON.parse(await readFile(vkPath, 'utf8'));
  if (!(await snarkjs.groth16.verify(vk, publicSignals, proof))) {
    fail('PROOF', `${kind} proof verify false`);
  }

  const proofPath = path.join(workDir, `${kind}.proof.json`);
  const pubPath = path.join(workDir, `${kind}.public.json`);
  await writeFile(proofPath, JSON.stringify(proof));
  await writeFile(pubPath, JSON.stringify(publicSignals));
  const adapter = await adaptSnarkjsGroth16({
    proof: { path: proofPath, sha256: await sha256File(proofPath) },
    publicSignals: { path: pubPath, sha256: await sha256File(pubPath) },
    verificationKey: { path: vkPath, sha256: await sha256File(vkPath) },
  });
  const adapterPath = path.join(workDir, `${kind}-adapter.json`);
  await writeFile(adapterPath, JSON.stringify(adapter));

  const unlocks = buildVerifierUnlocks({
    adapterPath,
    packetPath,
    outDir: path.join(workDir, `unlocks-${kind}`),
    requirePinLens: true,
  });

  const pf7Live = prep.settlementOutpoints.verifierCarriers.map((carrier, i) => ({
    lockingBytecode: carrier.lockingBytecode,
    unlockingBytecode: unlocks.dump[i].unlock,
    valueSatoshis: carrier.valueSatoshis,
    outpointTransactionHashWire: carrier.outpointTransactionHashWire,
    outpointIndex: Number(carrier.outpointIndex),
  }));

  const complete = await assembleCompleteSettlement({
    kind,
    bundleDirectory,
    expectedProfile,
    actionPacket: w1.actions[kind].actionPacket,
    minimumFeeRateSatoshisPerByte: 1n,
    feePrivateKey,
    feeSourceValueSatoshis: prep.outputValues.settlementFeeFundingSatoshis,
    bindingCarrierBaseSatoshis: bindingBase,
    stateCarrierBaseSatoshis: stateBase,
    preparationTransactionHashWire: prep.settlementOutpoints.binding.outpointTransactionHashWire,
    stateOutpointTransactionHashWire: Buffer.from(input.stateTxid, 'hex').reverse().toString('hex'),
    stateOutpointIndex: input.stateOutpointIndex ?? 0,
    pf7: pf7Live,
    ...(kind === 'withdrawal' ? { withdrawalLockingBytecode: input.withdrawalLockingBytecode } : {}),
  });

  const verdict = classifyCompleteSettlementVm(complete, true);
  if (!verdict.accepted) {
    fail('VM', `${kind} libauth reject ${JSON.stringify([...verdict.failedInputIndexes])}`);
  }

  const settleHex = Buffer.from(encodeTransaction(complete.transaction)).toString('hex');
  const settleTxid = Buffer.from(hash256(Buffer.from(settleHex, 'hex'))).reverse().toString('hex');

  await writeFile(path.join(workDir, `${kind}-prep.hex`), prepHex);
  await writeFile(path.join(workDir, `${kind}-settlement.hex`), settleHex);

  // Prep outputs locked to fee public key (hot) — typically settlementFeeFunding + large change.
  const feePub = (await instantiateSecp256k1()).derivePublicKeyCompressed(feePrivateKey);
  const feeLockHex = Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    createHash('ripemd160').update(createHash('sha256').update(feePub).digest()).digest(),
    Buffer.from([0x88, 0xac]),
  ]).toString('hex');
  const prepHotChange = [];
  for (let i = 0; i < prep.transaction.outputs.length; i++) {
    const o = prep.transaction.outputs[i];
    if (Buffer.from(o.lockingBytecode).toString('hex') === feeLockHex) {
      prepHotChange.push({ txid: prepTxid, vout: i, sats: Number(o.valueSatoshis) });
    }
  }

  const meta = {
    kind,
    prepTxid,
    settleTxid,
    wire: complete.measurements.wireBytes,
    maxUnlock: complete.measurements.maximumUnlockingBytes,
    proveMs,
    unlockMs: unlocks.ms,
    lens: unlocks.lens,
    digest: plan1.context.digestHex,
    unlockRoot: unlocks.unlockRoot,
    prepHotChange,
  };
  await writeFile(path.join(workDir, `${kind}-settlement-meta.json`), JSON.stringify(meta, null, 2));

  return {
    ...meta,
    prepHex,
    settleHex,
    feeSatoshis: complete.measurements.feeSatoshis.toString(),
    digests: digests1,
    complete,
    tipForest: w1.tipForest || null,
    preState: w1.actions[kind]?.action?.preState || w1.tipState || null,
    postState: w1.actions[kind]?.action?.postState || null,
  };
}

export { PIN_LENS };
