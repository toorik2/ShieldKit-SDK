#!/usr/bin/env node
/**
 * Chipnet chain E2E (local secrets + layer1-node BCHN).
 *
 * Steps:
 *  1) Create category-candidate UTXO (vout 0) from hot wallet
 *  2) Bridge profile with that genesis outpoint (reuse existing setup)
 *  3) Plan + sign + broadcast genesis (state NFT)
 *  4) Plan deposit prep against new pool (optional --deposit)
 *
 * Secrets: load from local artifact paths (never commit). Default:
 *   /home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/
 *
 * Usage (from monorepo root):
 *   node 03-create-your-own-pool/scripts/chain-e2e-chipnet.mjs \
 *     --setup-dir .cache/e2e-cli-full-20260725/setup \
 *     --out-dir .cache/chain-e2e-$(date +%Y%m%d-%H%M%S)
 */
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createReadStream } from 'node:fs';
import {
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';
import { createChainRpc } from '../packages/kit/chipnet-rpc.mjs';
import {
  broadcastStagedOperation,
  commitStagedOperation,
  stageOperation,
  transactionIdFromHex,
} from '../packages/kit/transaction-coordinator.mjs';

const monorepoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}
function flag(name) {
  return process.argv.includes(`--${name}`);
}

async function broadcastQualificationTransactions({
  rpc, operationRoot, label, transactions,
}) {
  const normalized = transactions.map(({ role, hex: transactionHex }) => ({
    role,
    hex: transactionHex,
    txid: transactionIdFromHex(transactionHex),
  }));
  const { journalPath } = stageOperation({
    poolDirectory: operationRoot,
    kind: `chain-e2e-${label}`,
    network: 'chipnet',
    setupMode: 'development-only',
    transactions: normalized,
    nextState: {
      schema: 'shieldkit/chipnet-qualification-state/v1',
      label,
      txids: normalized.map(({ role, txid }) => ({ role, txid })),
    },
    ledgerRecord: {
      schema: 'shieldkit/chipnet-qualification-ledger/v1',
      label,
      txids: normalized.map(({ role, txid }) => ({ role, txid })),
    },
  });
  await broadcastStagedOperation({ journalPath, rpc });
  commitStagedOperation({
    journalPath,
    statePath: path.join(operationRoot, 'state.json'),
    ledgerPath: path.join(operationRoot, 'ledger.jsonl'),
  });
  return normalized;
}

async function sha256File(file) {
  return new Promise((resolve, reject) => {
    const h = createHash('sha256');
    createReadStream(file)
      .on('data', (c) => h.update(c))
      .on('end', () => resolve(`sha256:${h.digest('hex')}`))
      .on('error', reject);
  });
}

function p2pkhLock(publicKey) {
  const sha = createHash('sha256').update(publicKey).digest();
  const h160 = createHash('ripemd160').update(sha).digest();
  return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), h160, Buffer.from([0x88, 0xac])]);
}
function schnorrUnlock(signature, publicKey) {
  return Buffer.concat([
    Buffer.from([0x41]), signature,
    Buffer.from([0x41, 0x21]), publicKey,
  ]);
}
const hex = (b) => Buffer.from(b).toString('hex');

async function signP2pkhInput({ secp, privateKey, publicKey, sourceOutput, transaction, inputIndex = 0 }) {
  const signingSerialization = Buffer.from(generateSigningSerializationBch(
    { inputIndex, sourceOutputs: [sourceOutput], transaction },
    {
      coveredBytecode: sourceOutput.lockingBytecode,
      signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
    },
  ));
  const digest = hash256(signingSerialization);
  const signature = secp.signMessageHashSchnorr(privateKey, digest);
  return Buffer.from(signature);
}

async function main() {
  const outDir = path.resolve(arg('out-dir', path.join(monorepoRoot, '.cache/chain-e2e-run')));
  const setupDir = path.resolve(arg('setup-dir', path.join(monorepoRoot, '.cache/e2e-cli-full-20260725/setup')));
  const walletRoot = path.resolve(arg(
    'wallets',
    '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4',
  ));
  const fundTxid = arg('fund-txid', '6535c087d74049f22dc375d0d06ff2d893563bf29529332252087c0c6cc80360');
  const fundVout = Number(arg('fund-vout', '1'));
  const categorySats = BigInt(arg('category-sats', '5000000')); // 0.05 BCH

  await mkdir(outDir, { recursive: true });
  const rpc = await createChainRpc({ network: 'chipnet' });
  console.error(`[chain-e2e] out=${outDir}`);

  const hotPriv = JSON.parse(await readFile(path.join(walletRoot, 'wallet-private.json'), 'utf8'));
  const hotPub = JSON.parse(await readFile(path.join(walletRoot, 'wallet-public.json'), 'utf8'));
  const privateKey = Buffer.from(hotPriv.privateKeyHex, 'hex');
  const publicKey = Buffer.from(hotPub.publicKeyHex, 'hex');
  const lock = Buffer.from(hotPub.lockingBytecodeHex, 'hex');
  const secp = await instantiateSecp256k1();

  // --- verify fund UTXO ---
  const utxo = await rpc.gettxout(fundTxid, fundVout);
  if (!utxo) throw new Error(`funding UTXO missing: ${fundTxid}:${fundVout}`);
  const fundValue = BigInt(Math.round(utxo.value * 1e8));
  console.error(`[chain-e2e] fund UTXO ${fundTxid}:${fundVout} = ${fundValue} sats`);
  if (fundValue <= categorySats + 1000n) throw new Error('funding UTXO too small');

  // --- Step 1: create category candidate (vout 0) ---
  // libauth encodeTransaction expects UI/display-order outpoint hashes (not reversed).
  const fundOutpointHash = Uint8Array.from(Buffer.from(fundTxid, 'hex'));
  const sizingTx = {
    version: 2,
    inputs: [{
      outpointTransactionHash: fundOutpointHash,
      outpointIndex: fundVout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      { valueSatoshis: categorySats, lockingBytecode: Uint8Array.from(lock) },
      { valueSatoshis: 1n, lockingBytecode: Uint8Array.from(lock) },
    ],
    locktime: 0,
  };
  // fee = wire size at 1 sat/B; iterate once
  let wire = Buffer.from(encodeTransaction({
    ...sizingTx,
    inputs: [{
      ...sizingTx.inputs[0],
      unlockingBytecode: schnorrUnlock(Buffer.alloc(64), publicKey),
    }],
  })).length;
  const fee = BigInt(wire);
  const change = fundValue - categorySats - fee;
  if (change <= 546n) throw new Error(`change dust: ${change}`);
  const unsigned = {
    version: 2,
    inputs: [{
      outpointTransactionHash: fundOutpointHash,
      outpointIndex: fundVout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      { valueSatoshis: categorySats, lockingBytecode: Uint8Array.from(lock) },
      { valueSatoshis: change, lockingBytecode: Uint8Array.from(lock) },
    ],
    locktime: 0,
  };
  const sourceOutput = { valueSatoshis: fundValue, lockingBytecode: Uint8Array.from(lock) };
  const sig = await signP2pkhInput({
    secp, privateKey, publicKey, sourceOutput, transaction: unsigned, inputIndex: 0,
  });
  const funded = {
    ...unsigned,
    inputs: [{ ...unsigned.inputs[0], unlockingBytecode: schnorrUnlock(sig, publicKey) }],
  };
  const fundHex = hex(Buffer.from(encodeTransaction(funded)));
  const [categoryBroadcast] = await broadcastQualificationTransactions({
    rpc,
    operationRoot: path.join(outDir, '.shieldkit/category-fund'),
    label: 'category-fund',
    transactions: [{ role: 'category-fund', hex: fundHex }],
  });
  const categoryTxid = categoryBroadcast.txid;
  console.error(`[chain-e2e] category fund broadcast: ${categoryTxid}`);
  await writeFile(path.join(outDir, '01-category-fund.json'), JSON.stringify({
    categoryTxid, categoryVout: 0, categorySats: categorySats.toString(), change: change.toString(), fundHex,
  }, null, 2));

  // --- Step 2: bridge profile with real genesis outpoint ---
  const { bridgeLocalSetupToProfile } = await import('../packages/profile/bridge.mjs');
  const setupMeta = path.join(setupDir, 'setup-metadata.json');
  const demoArt = path.join(monorepoRoot, '02-use-chipnet-demo-pool/bundle/artifacts');
  const liveArt = path.join(monorepoRoot, '.cache/profile-build-live/artifacts');
  const r1cs = path.join(monorepoRoot, '.cache/dev-setup-v2-strict/g1_relation.r1cs');
  const bundleDir = path.join(outDir, 'pool/bundle');
  await mkdir(path.join(outDir, 'pool'), { recursive: true });

  const built = await bridgeLocalSetupToProfile({
    destination: bundleDir,
    setupMetadata: { sourcePath: setupMeta, expectedSha256: await sha256File(setupMeta) },
    profile: {
      proofSystem: 'groth16', curve: 'bn254',
      relation: { id: 'shielded-action-v2' },
      publicInputAbi: { id: 'shielded-action-public-input-v1' },
    },
    toolchain: {
      compiler: { name: 'circom2', version: '0.2.23', source: { sourcePath: path.join(liveArt, 'circom2-cli.js') } },
      generator: { name: 'snarkjs', version: '0.7.6', source: { sourcePath: path.join(liveArt, 'snarkjs-cli.cjs') } },
    },
    network: { name: 'chipnet' },
    artifacts: [
      { id: 'bch-verifier-set', kind: 'bch-verifier-set', path: 'artifacts/verifier-set.bin', source: { sourcePath: path.join(demoArt, 'verifier-set.bin') } },
      { id: 'constraint-system', kind: 'constraint-system', path: 'artifacts/g1_relation.r1cs', source: { sourcePath: r1cs } },
      { id: 'proving-key', kind: 'proving-key', path: 'artifacts/final.zkey' },
      { id: 'public-input-abi', kind: 'public-input-abi', path: 'artifacts/public-input-abi.json', source: { sourcePath: path.join(demoArt, 'public-input-abi.json') } },
      { id: 'relation-definition', kind: 'relation-definition', path: 'artifacts/relation.json', source: { sourcePath: path.join(demoArt, 'relation.json') } },
      { id: 'verification-key', kind: 'verification-key', path: 'artifacts/verification_key.json' },
      { id: 'witness-generator', kind: 'witness-generator', path: 'artifacts/g1_relation.wasm', source: { sourcePath: path.join(demoArt, 'g1_relation.wasm') } },
    ],
    genesis: {
      categoryInputOutpoint: { txid: categoryTxid, vout: '0' },
      reserveCapSatoshis: '10000000',
    },
  });
  console.error(`[chain-e2e] profile ${built.profileId}`);
  console.error(`[chain-e2e] instance ${built.instanceId}`);

  const instance = {
    id: 'chain-e2e-pool',
    label: 'Chipnet chain E2E pool',
    role: 'custom',
    network: 'chipnet',
    setupMode: 'development-only',
    profileId: built.profileId,
    instanceId: built.instanceId,
    stateNftCategory: categoryTxid,
    reserveCapSatoshis: '10000000',
    denominationSatoshis: '10000000',
    categoryInputOutpoint: { txid: categoryTxid, vout: '0' },
    profileBundle: { path: 'bundle' },
    warnings: ['development-only Chipnet E2E instance'],
  };
  await writeFile(path.join(outDir, 'pool/instance.json'), JSON.stringify(instance, null, 2));

  // --- Step 3: genesis plan + finalize + broadcast ---
  const { loadInstance: loadInst, instanceToKitConfig: toCfg } = await import('../packages/profile/instance.mjs');
  const { createKit: mk } = await import('../packages/kit/kit.mjs');
  const inst = await loadInst(path.join(outDir, 'pool'));
  const kit = await mk(toCfg(inst));

  const categoryInput = {
    lockingBytecode: hotPub.lockingBytecodeHex,
    outpointIndex: '0',
    outpointTransactionHashWire: categoryTxid, // wire format: same as txid hex in our codebase?
    publicKey: hotPub.publicKeyHex,
    token: null,
    valueSatoshis: categorySats.toString(),
  };
  // Confirm wire format: genesis uses bytes() and reverse for outpoint — check categoryInputForProfile
  // profile.stateCategory = categoryInputOutpoint.txid as hex from manifest; outpointWire reversed compared to state category
  // In parseRequest: outpointWire = bytes(outpointTransactionHashWire)
  // categoryInputForProfile: expectedWire = Buffer.from(profile.stateCategory).reverse()
  // So outpointTransactionHashWire should be reverse of stateNftCategory if stateNftCategory is big-endian txid display...
  // build.mjs: stateNftCategory: input.genesis.categoryInputOutpoint?.txid  (same as we pass)
  // categoryInputForProfile: expectedWire = reverse(stateCategory) equals outpointWire
  // So outpointTransactionHashWire must be reverse(txid_display) if txid is standard bitcoin display order.
  // Bitcoin txids are displayed reversed from wire. Libauth outpointTransactionHash is typically internal/wire.
  // Looking at encode: outpointTransactionHash: reverse(outpointWire) when building tx if wire is display order.
  // In transactionFor: outpointTransactionHash: reverse(parsed.outpointWire)
  // So if we pass display txid as wire, reverse makes wire. BCHN uses display txid for gettxout.
  // categoryInputForProfile expects outpointWire === reverse(stateCategory) where stateCategory is the display txid string as hex.
  // So outpointTransactionHashWire should be reverse(display_txid) = wire order.
  // Actually: expectedWire = Buffer.from(profile.stateCategory).reverse() where stateCategory is hex string of display txid.
  // Buffer.from(txid,'hex').reverse() is wire form. So outpointTransactionHashWire should be wire form (reversed display).
  const displayTxid = categoryTxid;
  const wireTxid = Buffer.from(displayTxid, 'hex').reverse().toString('hex');
  // Wait - if stateNftCategory is display txid string "abc...", Buffer.from(stateCategory) parses hex as big-endian bytes of display form.
  // expectedWire = reverse(display_bytes) = wire.
  // parsed.outpointWire must equal wire. So pass wire as outpointTransactionHashWire.
  categoryInput.outpointTransactionHashWire = wireTxid;

  let plan;
  try {
    plan = await kit.planGenesis({ categoryInput });
  } catch (e) {
    // try display order if wire fails
    console.error('[chain-e2e] plan with wire failed, trying display order:', e.message);
    categoryInput.outpointTransactionHashWire = displayTxid;
    plan = await kit.planGenesis({ categoryInput });
  }
  await writeFile(path.join(outDir, '02-genesis-plan.json'), JSON.stringify({
    signingDigestHex: plan.signing.signingDigestHex,
    measurements: plan.measurements,
    profile: plan.profile,
  }, null, 2));

  const digest = Buffer.from(plan.signing.signingDigestHex, 'hex');
  const genesisSig = Buffer.from(secp.signMessageHashSchnorr(privateKey, digest));
  const finalized = await kit.finalizeGenesis({ categoryInput }, hex(genesisSig));
  await writeFile(path.join(outDir, '03-genesis-tx.json'), JSON.stringify({
    transactionId: finalized.transactionId,
    transactionHex: finalized.transactionHex,
    measurements: finalized.measurements,
  }, null, 2));

  const [genesisBroadcast] = await broadcastQualificationTransactions({
    rpc,
    operationRoot: path.join(outDir, '.shieldkit/genesis'),
    label: 'genesis',
    transactions: [{ role: 'genesis', hex: finalized.transactionHex }],
  });
  const genesisTxid = genesisBroadcast.txid;
  console.error(`[chain-e2e] GENESIS BROADCAST: ${genesisTxid}`);

  // --- Step 4: deposit request template using change as fee funding if possible ---
  const { parsePf7CarrierAuthority } = await import('../packages/prove/authority.mjs');
  const vs = JSON.parse(await readFile(path.join(bundleDir, 'artifacts/verifier-set.bin'), 'utf8'));
  const authority = parsePf7CarrierAuthority(vs);
  // Use change output of category fund as fee funding for deposit prep (vout 1)
  const depositRequest = {
    kind: 'deposit',
    bindingCarrierBaseValueSatoshis: authority.settlementKernel.artifact.constants.bindingCarrierBaseSatoshis,
    bindingLockingBytecode: authority.settlementKernel.bindingLock.toString('hex'),
    fundingOutpointIndex: '1',
    fundingOutpointTransactionHashWire: Buffer.from(categoryTxid, 'hex').reverse().toString('hex'),
    fundingPublicKey: hotPub.publicKeyHex,
    fundingSourceValueSatoshis: change.toString(),
    settlementFeeFundingSatoshis: '100000',
  };
  // try display order for funding if needed
  await writeFile(path.join(outDir, '04-deposit-request.json'), JSON.stringify(depositRequest, null, 2));

  let depositPrep = null;
  try {
    const prepPlan = await kit.planCompletePreparation(depositRequest);
    const signing = await kit.preparationSigningRequest(depositRequest);
    const prepDigest = Buffer.from(signing.digestHex, 'hex');
    const prepSig = Buffer.from(secp.signMessageHashSchnorr(privateKey, prepDigest));
    const finalizedPrep = await kit.finalizeCompletePreparation(depositRequest, hex(prepSig));
    // encode prep tx if available
    let prepHex = finalizedPrep.transactionHex
      || (finalizedPrep.transaction ? hex(Buffer.from(encodeTransaction(finalizedPrep.transaction))) : null);
    depositPrep = {
      signingDigestHex: signing.digestHex,
      prepHex: prepHex ? `${prepHex.slice(0, 32)}…` : null,
      wireBytes: prepHex?.length / 2,
      keys: Object.keys(finalizedPrep),
    };
    if (prepHex && flag('broadcast-prep')) {
      const [prepBroadcast] = await broadcastQualificationTransactions({
        rpc,
        operationRoot: path.join(outDir, '.shieldkit/deposit-preparation'),
        label: 'deposit-preparation',
        transactions: [{ role: 'preparation', hex: prepHex }],
      });
      depositPrep.broadcastTxid = prepBroadcast.txid;
      console.error(`[chain-e2e] PREP BROADCAST: ${prepBroadcast.txid}`);
    }
    await writeFile(path.join(outDir, '05-deposit-prep.json'), JSON.stringify(depositPrep, null, 2));
  } catch (e) {
    depositPrep = { error: e.message, note: 'prep may need funding wire-order tweak or more sats for deposit' };
    await writeFile(path.join(outDir, '05-deposit-prep.json'), JSON.stringify(depositPrep, null, 2));
    console.error('[chain-e2e] deposit prep failed:', e.message);
  }

  const summary = {
    ok: true,
    network: 'chipnet',
    categoryFundTxid: categoryTxid,
    genesisTxid,
    profileId: built.profileId,
    instanceId: built.instanceId,
    poolDir: path.join(outDir, 'pool'),
    depositPrep,
    explorerGenesis: `https://chipnet.chaingraph.cash/tx/${genesisTxid}`,
    note: 'Settlement (prove+PF7+assemble) not auto-run here; genesis is the create-pool on-chain proof.',
  };
  await writeFile(path.join(outDir, 'SUMMARY.json'), JSON.stringify(summary, null, 2));
  console.log(JSON.stringify(summary, null, 2));
}

main().catch((e) => {
  console.error('[chain-e2e] FAIL', e.message || e);
  process.exit(1);
});
