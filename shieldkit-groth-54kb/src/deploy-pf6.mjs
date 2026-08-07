// ShieldKit-54KB — pf6 pool deployment (chipnet, zero-conf).
// Phase A: source (funding) tx -> instanceId. Phase B: genesis (pool-create).
// Signing in-process; private keys never printed/logged.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';

const FOLDER = '/home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb';
const WALLET = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-private.json';

const libauthUrl = 'file:///home/toorik/Projects/ZK-Proofs/shieldkit-sdk/shieldkit-groth-54kb/vendor/verifier-workspace/build/node_modules/@bitauth/libauth/build/index.js';
const la = await import(libauthUrl);
const { hexToBin, binToHex, encodeTransaction, decodeTransaction, generateSigningSerializationBch, hash256, secp256k1, encodeDataPush, encodeLockingBytecodeP2sh32 } = la;

const wallet = JSON.parse(readFileSync(WALLET, 'utf8'));
const priv = Buffer.from(wallet.privateKeyHex, 'hex');
const pub = wallet.publicKeyHex;
const hotLock = wallet.lockingBytecodeHex; // P2PKH

const SIGHASH_TYPE = 97; // 0x61 = allOutputsAllUtxos (product V2_FUNDING_SIGHASH_TYPE)
const signP2pkh = (tx, sourceLock, sourceValue, inputIndex) => {
  const serialization = generateSigningSerializationBch(
    { inputIndex, sourceOutputs: [{ lockingBytecode: hexToBin(sourceLock), valueSatoshis: sourceValue }], transaction: tx },
    { coveredBytecode: hexToBin(sourceLock), signingSerializationType: Uint8Array.of(SIGHASH_TYPE) },
  );
  const digest = hash256(serialization);
  const schnorr = secp256k1.signMessageHashSchnorr(priv, digest);
  const unlock = Buffer.concat([
    encodeDataPush(Uint8Array.from([...schnorr, SIGHASH_TYPE])),
    encodeDataPush(Uint8Array.from(Buffer.from(pub, 'hex'))),
  ]);
  if (unlock.length !== 100) throw new Error('P2PKH unlock must be 100 B, got ' + unlock.length);
  return unlock;
};

const txidOf = (hex) => binToHex(hash256(hexToBin(hex)).reverse());
const sha256file = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');

// ---- inputs ----
const fundingUtxo = JSON.parse(readFileSync('/tmp/pf6-funding-utxo.json', 'utf8'));
fundingUtxo.sats = BigInt(fundingUtxo.sats);
const sourceFundSats = 2_000_000n;

// ---- Phase A: source tx ----
const sourceTx = {
  version: 2,
  inputs: [{
    outpointTransactionHash: hexToBin(fundingUtxo.txid), outpointIndex: fundingUtxo.vout,
    sequenceNumber: 0xfffffffe,
    unlockingBytecode: new Uint8Array(),
  }],
  outputs: [
    { lockingBytecode: hexToBin(hotLock), valueSatoshis: sourceFundSats },
  ],
  locktime: 0,
};
// fee: 1 sat/B + 1; sign AFTER finalizing outputs; iterate to convergence
let sourceSigned = null;
let change = 0n;
for (let i = 0; i < 5; i++) {
  sourceTx.outputs[1] = { lockingBytecode: hexToBin(hotLock), valueSatoshis: change };
  const unlock = signP2pkh(sourceTx, hotLock, fundingUtxo.sats, 0);
  sourceTx.inputs[0].unlockingBytecode = unlock;
  const raw = binToHex(encodeTransaction(sourceTx));
  const requiredFee = BigInt(raw.length / 2 + 1);
  const actualFee = fundingUtxo.sats - sourceFundSats - change;
  if (actualFee === requiredFee) { sourceSigned = raw; break; }
  change = fundingUtxo.sats - sourceFundSats - requiredFee;
}
const sourceTxid = txidOf(sourceSigned);
console.log('SOURCE TX built:', sourceTxid, '| bytes:', sourceSigned.length / 2);
writeFileSync(path.join(FOLDER, 'evidence/03-implementation/deploy-source.hex'), sourceSigned);
writeFileSync('/tmp/pf6-source-txid.json', JSON.stringify({ txid: sourceTxid, hex: sourceSigned }));

// instanceId = reversed source txid (product genesis.mjs rule:
// Buffer.from(sourceTxid, 'hex').reverse().toString('hex'))
const instanceId = Buffer.from(sourceTxid, 'hex').reverse().toString('hex');
console.log('INSTANCE ID:', instanceId);
writeFileSync('/tmp/pf6-instance.json', JSON.stringify({ instanceId, sourceTxid, sourceHex: sourceSigned }));
