#!/usr/bin/env node
/**
 * Chipnet: create a mutable CashToken NFT with 128-byte SKS2 commitment.
 * Category is the txid of the genesis (vout 0 rule). No minting authority left.
 * State locked to hot P2PKH for custody (covenant locks require cashc+unlock-builder
 * foundation completion — see v2-foundation-BLOCKED.md).
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
  binToHex,
  hexToBin,
} from '@bitauth/libauth';
import { encodePoolStateV2, emptyGenesisStateFields } from '../state.mjs';
import { emptyNoteRoot } from '../trees/note-tree.mjs';
import { emptyNullifierRoot } from '../trees/indexed-nullifier.mjs';
import { PLAYGROUND_MAXIMUM_LIVE_NOTES } from '../constants.mjs';

const WALLET_DIR = '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4';
const HOT = 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';
const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../.cache/v2-direct-nft-genesis');

function shellQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}
function rpc(method, params = []) {
  const tokens = params.map((p) => (
    typeof p === 'string' || typeof p === 'number' || typeof p === 'boolean'
      ? shellQuote(String(p))
      : shellQuote(JSON.stringify(p))
  ));
  const cmd = [
    'sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf',
    method,
    ...tokens,
  ].join(' ');
  const out = execFileSync('ssh', ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', 'layer1-node', cmd], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const t = out.trim();
  if (!t) return null;
  try { return JSON.parse(t); } catch { return t.replace(/^"|"$/g, ''); }
}

function sha256(b) {
  return createHash('sha256').update(b).digest();
}
function base58Encode(buffer) {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let zeros = 0;
  while (zeros < buffer.length && buffer[zeros] === 0) zeros += 1;
  const digits = [0];
  for (let i = zeros; i < buffer.length; i += 1) {
    let carry = buffer[i];
    for (let j = 0; j < digits.length; j += 1) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let str = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i -= 1) str += ALPHABET[digits[i]];
  return str;
}

function loadWallet() {
  const priv = JSON.parse(readFileSync(path.join(WALLET_DIR, 'wallet-private.json'), 'utf8'));
  return {
    privateKey: Buffer.from(priv.privateKeyHex, 'hex'),
    publicKey: Buffer.from(priv.publicKeyHex, 'hex'),
    lockingBytecode: Buffer.from(priv.lockingBytecodeHex, 'hex'),
    address: priv.address,
  };
}

function wifFromPriv(priv) {
  const payload = Buffer.concat([Buffer.from([0xef]), priv, Buffer.from([0x01])]);
  const chk = sha256(sha256(payload)).subarray(0, 4);
  return base58Encode(Buffer.concat([payload, chk]));
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  const wallet = loadWallet();
  const scan = rpc('scantxoutset', ['start', [`addr(${HOT})`]]);
  const unspents = (scan.unspents || [])
    .map((u) => ({
      txid: u.txid,
      vout: u.vout,
      valueSats: BigInt(Math.round(u.amount * 1e8)),
      scriptPubKey: u.scriptPubKey,
    }))
    .filter((u) => u.valueSats >= 50_000n)
    .sort((a, b) => Number(b.valueSats - a.valueSats));
  // Prefer vout 0 for category creation (BCH CashTokens: category = outpoint txid when spending vout 0)
  let cat = unspents.find((u) => u.vout === 0 && u.valueSats >= 100_000n);
  if (!cat) {
    // Create a vout-0 UTXO first via split
    const fund = unspents[0];
    if (!fund) throw new Error('no UTXOs');
    const half = Number(fund.valueSats / 2n) / 1e8;
    const raw = rpc('createrawtransaction', [
      [{ txid: fund.txid, vout: fund.vout }],
      { [HOT]: half },
    ]);
    const signed = rpc('signrawtransactionwithkey', [
      raw,
      [wifFromPriv(wallet.privateKey)],
      [{
        txid: fund.txid,
        vout: fund.vout,
        scriptPubKey: fund.scriptPubKey,
        amount: Number(fund.valueSats) / 1e8,
      }],
    ]);
    if (!signed?.complete) throw new Error(`split sign failed: ${JSON.stringify(signed)}`);
    const accept = rpc('testmempoolaccept', [[signed.hex]]);
    console.log('split accept', JSON.stringify(accept));
    const splitTxid = rpc('sendrawtransaction', [signed.hex]);
    console.log('splitTxid', splitTxid);
    // Wait isn't available; re-scan may not see mempool. Use createrawtransaction with token if node supports.
    // Fallback: use token-aware RPC if available.
    cat = {
      txid: splitTxid,
      vout: 0,
      valueSats: BigInt(Math.round(half * 1e8)),
      scriptPubKey: wallet.lockingBytecode.toString('hex'),
      mempool: true,
    };
  }

  const profileId = createHash('sha256').update('v2-nft-genesis-profile').digest('hex');
  // instanceId will equal category = genesis txid once known; provisional for state encoding
  // Empty state with note/nullifier roots at depth 16
  const { createNoteTree } = await import('../trees/note-tree.mjs');
  const { createIndexedNullifierTree } = await import('../trees/indexed-nullifier.mjs');
  const nt = createNoteTree({ depth: 16 });
  const nft = createIndexedNullifierTree({ depth: 16 });
  const state = emptyGenesisStateFields({
    profileId,
    noteRoot: nt.emptyRoot,
    nullifierRoot: nft.root(),
    maximumLiveNotes: PLAYGROUND_MAXIMUM_LIVE_NOTES,
  });
  const commitment = encodePoolStateV2(state);
  if (commitment.length !== 128) throw new Error('commitment not 128');

  // Use bitcoin-cli token-aware APIs if present (BCHN)
  // createrawtransaction with token data is nonstandard on bitcoin-cli for BCH.
  // Prefer libauth encode + signrawtransactionwithkey after building hex.

  const secp = await instantiateSecp256k1();
  const stateBase = 2000n;
  const fee = 1000n;
  const change = cat.valueSats - stateBase - fee;
  if (change < 546n) throw new Error('insufficient for genesis');

  // Category created when input is vout 0; category bytes = txid of this genesis (unknown until signed).
  // Build transaction with placeholder category = zeros, then... actually category is determined by
  // prevout: category = hash of genesis input outpoint's txid (the category-creating input's txid).
  // So category = cat.txid (the prevout transaction id), when spending vout 0 of cat.
  const category = Buffer.from(cat.txid, 'hex');

  const token = {
    category: Uint8Array.from(category),
    amount: 0n,
    nft: {
      capability: 'mutable',
      commitment: Uint8Array.from(commitment),
    },
  };

  const tx = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(Buffer.from(cat.txid, 'hex').reverse()),
      outpointIndex: cat.vout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      {
        valueSatoshis: stateBase,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
        token,
      },
      {
        valueSatoshis: change,
        lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
      },
    ],
  };

  // Sign with Schnorr ALL|FORKID
  const sourceOutputs = [{
    valueSatoshis: cat.valueSats,
    lockingBytecode: Uint8Array.from(wallet.lockingBytecode),
  }];

  let signingSerialization;
  try {
    signingSerialization = generateSigningSerializationBch(
      { inputIndex: 0, sourceOutputs, transaction: tx },
      {
        coveredBytecode: Uint8Array.from(wallet.lockingBytecode),
        signingSerializationType: Uint8Array.of(
          // eslint-disable-next-line no-bitwise
          SigningSerializationTypeBch.allOutputs | SigningSerializationTypeBch.forkId,
        ),
      },
    );
  } catch (e) {
    // Older/newer libauth API shape
    console.error('signing serialization failed', e.message);
    // Fall back to bitcoin-cli path cannot do tokens easily.
    throw e;
  }

  const digest = hash256(signingSerialization);
  const sig = secp.signMessageHashSchnorr(wallet.privateKey, digest);
  // unlock: push 64-byte sig+sighash, push pubkey
  const sighashByte = 0x41;
  const sigWithType = Buffer.concat([Buffer.from(sig), Buffer.from([sighashByte])]);
  const unlock = Buffer.concat([
    Buffer.from([sigWithType.length]),
    sigWithType,
    Buffer.from([wallet.publicKey.length]),
    wallet.publicKey,
  ]);
  tx.inputs[0].unlockingBytecode = Uint8Array.from(unlock);

  const encoded = Buffer.from(encodeTransaction(tx));
  console.log('txBytes', encoded.length);
  console.log('commitmentBytes', commitment.length);
  console.log('category', category.toString('hex'));

  const accept = rpc('testmempoolaccept', [[encoded.toString('hex')]]);
  console.log('testmempoolaccept', JSON.stringify(accept));
  const row = Array.isArray(accept) ? accept[0] : accept;
  let txid = null;
  if (row?.allowed) {
    txid = rpc('sendrawtransaction', [encoded.toString('hex')]);
    console.log('txid', txid);
  } else {
    console.log('NOT broadcast — mempool rejected or tokens unsupported in this path');
  }

  const evidence = {
    allowed: Boolean(row?.allowed),
    rejectReason: row?.['reject-reason'] || row?.['reject-reason'] || null,
    testmempoolaccept: row,
    txid: txid && String(txid).toLowerCase(),
    txBytes: encoded.length,
    commitmentHex: commitment.toString('hex'),
    categoryHex: category.toString('hex'),
    state,
    input: { txid: cat.txid, vout: cat.vout, valueSats: cat.valueSats.toString() },
  };
  writeFileSync(path.join(OUT, 'evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify(evidence, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
