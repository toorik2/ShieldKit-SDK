#!/usr/bin/env node
/**
 * Create a ShieldKit pool directory.
 *
 * Modes:
 *   scaffold (default): copy pin profile bundle → instance dir (existing tip)
 *   --with-genesis: fund category UTXO → rebuild profile for new outpoint →
 *                   plan/finalize genesis → optional --broadcast
 *
 * Usage:
 *   npm run create-pool -- --out ./my-pool
 *   npm run create-pool -- --out ./new-pool --with-genesis \
 *     --wallets .cache/e2e-full-20260725/local-wallets.json \
 *     --fund-txid <txid> --fund-vout 1 [--broadcast]
 *   # or auto-pick live fund (gettxout-verified; skips scantxoutset phantoms):
 *   npm run create-pool -- --out ./new-pool --with-genesis --scan-fund --broadcast
 *   # privacy-ready capacity (default 16 live notes = 1.6 BCH reserve):
 *   npm run create-pool -- --out ./new --with-genesis --scan-fund --max-notes 16 --broadcast
 *   # mainnet (default remains chipnet):
 *   npm run create-pool -- --out ./mainnet-pool --with-genesis --network mainnet \
 *     --wallets ./mainnet-wallets.json --scan-fund --broadcast \
 *     --i-understand-mainnet --allow-development-on-mainnet
 */
import { createHash } from 'node:crypto';
import {
  cpSync, existsSync, mkdirSync, readFileSync, writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
} from '../packages/action/node_modules/@bitauth/libauth/build/index.js';
import { buildVerifierProfileBundle } from '../packages/profile/build.mjs';
import { loadVerifierProfileBundle } from '../packages/profile/load.mjs';
import {
  planChipnetGenesisTransaction,
  finalizeChipnetGenesisTransaction,
} from '../packages/profile/genesis.mjs';
import { resolveUnlockRoot, resolveLeanRoot, PIN_LENS } from '../packages/unlock-builder/index.mjs';
import {
  DEFAULT_MAX_NOTES,
  resolvePoolCapacity,
  capacityFromReserveCap,
  capacitySummary,
} from '../packages/kit/pool-capacity.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const DEFAULT_PIN_ART = path.join(ROOT, '.cache/profile-build-live/artifacts');
const DEFAULT_PIN_BUNDLE = path.join(ROOT, '.cache/profile-build-live/profile-bundle');

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}
function hasFlag(name) {
  return process.argv.includes(`--${name}`);
}

const SSH_OPTS = ['-o', 'BatchMode=yes', '-o', 'LogLevel=ERROR', '-o', 'ConnectTimeout=20'];

function bchnSendHex(hex) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `cat > /tmp/sk-create-pool.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf sendrawtransaction "$(cat /tmp/sk-create-pool.hex)" true`], {
    encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`sendraw: ${r.stderr || r.stdout}`);
  return (r.stdout || '').trim();
}

function bchnTestMempool(hex) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `cat > /tmp/sk-create-pool.hex && sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf testmempoolaccept "[\\"$(cat /tmp/sk-create-pool.hex)\\"]"`], {
    encoding: 'utf8', input: hex, maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`testmempool: ${r.stderr || r.stdout}`);
  return JSON.parse(r.stdout);
}

function bchnGetTxOut(txid, vout) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf gettxout ${txid} ${vout} true`], { encoding: 'utf8' });
  if (r.status !== 0) return null;
  const t = (r.stdout || '').trim();
  if (!t || t === 'null') return null;
  try { return JSON.parse(t); } catch { return null; }
}

/** Parse first top-level JSON object from mixed bitcoin-cli stdout. */
function parseFirstJsonObject(raw) {
  const start = raw.indexOf('{');
  if (start < 0) throw new Error('no JSON object in output');
  let depth = 0;
  for (let i = start; i < raw.length; i++) {
    const ch = raw[i];
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return JSON.parse(raw.slice(start, i + 1));
    }
  }
  throw new Error('unterminated JSON object');
}

function bchnScanAddr(address) {
  const r = spawnSync('ssh', [...SSH_OPTS, 'layer1-node',
    `sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf scantxoutset start '["addr(${address})"]'`], {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`scantxoutset: ${r.stderr || r.stdout}`);
  return parseFirstJsonObject(r.stdout || '');
}

/**
 * Pick largest live funding UTXO ≥ minSats.
 * Always gettxout-verifies scan hits when gettxout is real (not electrum partial).
 * @param {object} rpc createChainRpc handle
 * @param {string} address
 * @param {number} minSats
 * @param {string} [lockingBytecodeHex]
 */
async function pickVerifiedFund(rpc, address, minSats, lockingBytecodeHex) {
  let listed;
  if (rpc.backend === 'layer1-ssh') {
    const scan = bchnScanAddr(address);
    listed = (scan.unspents || []).map((u) => ({
      txid: u.txid,
      vout: Number(u.vout),
      sats: Math.round(Number(u.amount) * 1e8),
    }));
  } else {
    listed = await rpc.scanAddress(address, lockingBytecodeHex);
  }
  const rows = (listed || [])
    .filter((u) => Number(u.sats) >= minSats)
    .sort((a, b) => Number(b.sats) - Number(a.sats));
  let staleSkipped = 0;
  for (const cand of rows) {
    let sats = Number(cand.sats);
    if (rpc.backend === 'layer1-ssh' || rpc.backend === 'jsonrpc') {
      const u = rpc.backend === 'layer1-ssh'
        ? bchnGetTxOut(cand.txid, cand.vout)
        : await rpc.gettxout(cand.txid, cand.vout);
      if (!u || u._partial) {
        // electrum partial / spent
        if (!u) { staleSkipped++; continue; }
      } else if (u.value != null) {
        sats = Math.round(Number(u.value) * 1e8);
      }
    }
    if (sats < minSats) {
      staleSkipped++;
      continue;
    }
    return {
      txid: cand.txid,
      vout: cand.vout,
      sats,
      staleSkipped,
      candidates: rows.length,
    };
  }
  throw new Error(
    `no live funding UTXO ≥ ${minSats} sats for ${address} `
    + `(scan candidates=${rows.length}, phantoms_skipped=${staleSkipped}; pass --fund-txid)`,
  );
}

function p2pkh(publicKey) {
  const sha = createHash('sha256').update(publicKey).digest();
  const h160 = createHash('ripemd160').update(sha).digest();
  return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), h160, Buffer.from([0x88, 0xac])]);
}

function schnorrUnlock(signature, publicKey) {
  return Buffer.concat([Buffer.of(0x41), signature, Buffer.of(0x41, 0x21), publicKey]);
}

async function scaffoldOnly(out, bundleSrc) {
  if (!existsSync(bundleSrc)) throw new Error(`profile bundle missing: ${bundleSrc}`);
  if (existsSync(out)) throw new Error(`out already exists: ${out}`);
  const loaded = await loadVerifierProfileBundle(bundleSrc);
  mkdirSync(out, { recursive: true });
  cpSync(bundleSrc, path.join(out, 'bundle'), { recursive: true });
  mkdirSync(path.join(out, 'notes'), { recursive: true });
  mkdirSync(path.join(out, 'runs'), { recursive: true });
  const instance = {
    schema: 'shieldkit/pool-instance/v1',
    role: 'custom',
    network: loaded.manifest.network?.name || loaded.manifest.network || 'chipnet',
    profileId: loaded.manifest.identity.profileId,
    instanceId: loaded.manifest.genesis.instanceId,
    bundleDirectory: 'bundle',
    unlockPinLens: PIN_LENS,
    createdAt: new Date().toISOString(),
    mode: 'scaffold-existing-tip',
  };
  writeFileSync(path.join(out, 'instance.json'), JSON.stringify(instance, null, 2));
  // U-03: wire tip when operator supplies --state-txid or when pin tip file exists
  const tipFromArg = process.argv.includes('--state-txid')
    ? process.argv[process.argv.indexOf('--state-txid') + 1]
    : null;
  const tipFile = path.join(ROOT, '.cache/live-battery/run-20260724/state.json');
  let tip = tipFromArg || null;
  if (!tip && existsSync(tipFile)) {
    try {
      const live = JSON.parse(readFileSync(tipFile, 'utf8'));
      // only auto-wire if instance matches live profile tip instance
      if (live.stateTxid && live.instanceId === instance.instanceId) tip = live.stateTxid;
      else if (live.stateTxid && !live.instanceId) {
        // live battery tip for same pin profile (common dev path)
        tip = live.stateTxid;
      }
    } catch { /* ignore */ }
  }
  writeFileSync(path.join(out, 'state.json'), JSON.stringify({
    stateTxid: tip,
    tipSource: tipFromArg ? 'cli' : (tip ? 'live-battery-auto' : null),
    tipNote: tip
      ? 'Tip wired for act. Override with --state-txid or after --with-genesis.'
      : 'No tip: pass --state-txid <txid> or run create-pool --with-genesis --broadcast (U-03).',
    feeUtxos: [],
    history: [],
  }, null, 2));
  return { instance, loaded, tip };
}

async function withGenesis(out, opts) {
  if (existsSync(out)) throw new Error(`out already exists: ${out}`);
  const pinArt = path.resolve(opts.pinArtifacts || DEFAULT_PIN_ART);
  const wallets = JSON.parse(readFileSync(path.resolve(opts.wallets), 'utf8'));
  const hot = wallets.hot;
  const privateKey = Buffer.from(hot.privateKeyHex, 'hex');
  const publicKey = Buffer.from(hot.publicKeyHex, 'hex');
  const lock = Buffer.from(hot.lockingBytecodeHex, 'hex');
  const fundTxid = opts.fundTxid;
  const fundVout = Number(opts.fundVout);
  const categorySats = BigInt(opts.categorySats || '5000000');
  const capacity = opts.capacity || resolvePoolCapacity(DEFAULT_MAX_NOTES);

  const rpc = opts.rpc;
  if (!rpc) throw new Error('withGenesis requires opts.rpc (createChainRpc)');
  let fundValue;
  if (opts.fundSats != null) {
    fundValue = BigInt(opts.fundSats);
  } else {
    const utxo = rpc.backend === 'layer1-ssh'
      ? bchnGetTxOut(fundTxid, fundVout)
      : await rpc.gettxout(fundTxid, fundVout);
    if (!utxo || (utxo._partial && opts.fundSats == null)) {
      throw new Error(
        `funding UTXO missing ${fundTxid}:${fundVout}`
        + (utxo?._partial ? ' (electrum partial — pass fund sats via --scan-fund)' : ''),
      );
    }
    fundValue = BigInt(Math.round(Number(utxo.value) * 1e8));
  }
  if (fundValue <= categorySats + 1000n) throw new Error('funding UTXO too small');

  const secp = await instantiateSecp256k1();
  // libauth encodeTransaction expects UI/display-order outpoint hashes (not reversed).
  const fundOutpointHash = Uint8Array.from(Buffer.from(fundTxid, 'hex'));
  const sourceOutput = { valueSatoshis: fundValue, lockingBytecode: Uint8Array.from(lock) };
  // size with dummy schnorr unlock (1 sat/B)
  const sizing = {
    version: 2,
    locktime: 0,
    inputs: [{
      outpointTransactionHash: fundOutpointHash,
      outpointIndex: fundVout,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: schnorrUnlock(Buffer.alloc(64), publicKey),
    }],
    outputs: [
      { valueSatoshis: categorySats, lockingBytecode: Uint8Array.from(lock) },
      { valueSatoshis: 1n, lockingBytecode: Uint8Array.from(lock) },
    ],
  };
  const fee = BigInt(Buffer.from(encodeTransaction(sizing)).length);
  const change = fundValue - categorySats - fee;
  if (change <= 546n) throw new Error(`change dust: ${change}`);
  const unsigned = {
    version: 2,
    locktime: 0,
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
  };
  const ss = generateSigningSerializationBch({
    inputIndex: 0, sourceOutputs: [sourceOutput], transaction: unsigned,
  }, {
    coveredBytecode: sourceOutput.lockingBytecode,
    signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
  });
  const sig = secp.signMessageHashSchnorr(privateKey, hash256(ss));
  if (typeof sig === 'string') throw new Error(sig);
  unsigned.inputs[0].unlockingBytecode = schnorrUnlock(Buffer.from(sig), publicKey);
  const fundHex = Buffer.from(encodeTransaction(unsigned)).toString('hex');
  if (BigInt(Buffer.from(fundHex, 'hex').length) !== fee) {
    throw new Error(`fee size mismatch planned=${fee} actual=${Buffer.from(fundHex, 'hex').length}`);
  }

  const fundAccept = rpc.backend === 'layer1-ssh'
    ? bchnTestMempool(fundHex)
    : await rpc.testmempoolaccept(fundHex);
  if (!fundAccept?.[0]?.allowed) throw new Error(`category fund rejected: ${JSON.stringify(fundAccept)}`);
  let categoryTxid;
  if (opts.broadcast) {
    categoryTxid = rpc.backend === 'layer1-ssh'
      ? bchnSendHex(fundHex)
      : await rpc.sendrawtransaction(fundHex);
  } else {
    categoryTxid = Buffer.from(hash256(Buffer.from(fundHex, 'hex'))).reverse().toString('hex');
  }

  // --- rebuild profile bound to category outpoint ---
  mkdirSync(out, { recursive: true });
  mkdirSync(path.join(out, 'notes'), { recursive: true });
  mkdirSync(path.join(out, 'runs'), { recursive: true });
  const bundleDir = path.join(out, 'bundle');
  const setupMeta = JSON.parse(readFileSync(path.join(pinArt, 'setup-metadata.json'), 'utf8'));
  const setup = {
    mode: setupMeta.setup.mode,
    provenance: setupMeta.setup.provenance,
    material: setupMeta.setup.material,
  };
  const built = await buildVerifierProfileBundle({
    destination: bundleDir,
    profile: {
      proofSystem: 'groth16',
      curve: 'bn254',
      relation: { id: 'shielded-action-v2' },
      publicInputAbi: { id: 'shielded-action-public-input-v1' },
    },
    setup,
    toolchain: {
      compiler: {
        name: 'circom2',
        version: '0.2.23',
        source: { sourcePath: path.join(pinArt, 'circom2-cli.js') },
      },
      generator: {
        name: 'snarkjs',
        version: '0.7.6',
        source: { sourcePath: path.join(pinArt, 'snarkjs-cli.cjs') },
      },
    },
    network: { name: opts.network || 'chipnet' },
    artifacts: [
      { id: 'bch-verifier-set', kind: 'bch-verifier-set', path: 'artifacts/verifier-set.bin', source: { sourcePath: path.join(pinArt, 'verifier-set.bin') } },
      { id: 'constraint-system', kind: 'constraint-system', path: 'artifacts/g1_relation.r1cs', source: { sourcePath: path.join(pinArt, 'g1_relation.r1cs') } },
      { id: 'proving-key', kind: 'proving-key', path: 'artifacts/final.zkey', source: { sourcePath: path.join(pinArt, 'final.zkey') } },
      { id: 'public-input-abi', kind: 'public-input-abi', path: 'artifacts/public-input-abi.json', source: { sourcePath: path.join(pinArt, 'public-input-abi.json') } },
      { id: 'relation-definition', kind: 'relation-definition', path: 'artifacts/relation.json', source: { sourcePath: path.join(pinArt, 'relation.json') } },
      { id: 'verification-key', kind: 'verification-key', path: 'artifacts/verification_key.json', source: { sourcePath: path.join(pinArt, 'verification_key.json') } },
      { id: 'witness-generator', kind: 'witness-generator', path: 'artifacts/g1_relation.wasm', source: { sourcePath: path.join(pinArt, 'g1_relation.wasm') } },
    ],
    genesis: {
      categoryInputOutpoint: { txid: categoryTxid, vout: '0' },
      reserveCapSatoshis: capacity.reserveCapSatoshis,
    },
  });

  const categoryInput = {
    lockingBytecode: hot.lockingBytecodeHex,
    outpointIndex: '0',
    // wire order: reverse of display txid
    outpointTransactionHashWire: Buffer.from(categoryTxid, 'hex').reverse().toString('hex'),
    publicKey: hot.publicKeyHex,
    token: null,
    valueSatoshis: categorySats.toString(),
  };

  const genesisReq = {
    categoryInput,
    bundleDirectory: bundleDir,
    expectedProfile: {
      profileId: built.profileId,
      instanceId: built.instanceId,
      network: opts.network || 'chipnet',
    },
    bindingCarrierBaseSatoshis: '1000',
    stateCarrierBaseSatoshis: '1080',
    minimumFeeRateSatoshisPerByte: '1',
  };

  let plan;
  try {
    plan = await planChipnetGenesisTransaction(genesisReq);
  } catch (e) {
    // try display order
    categoryInput.outpointTransactionHashWire = categoryTxid;
    plan = await planChipnetGenesisTransaction(genesisReq);
  }

  const digest = Buffer.from(plan.signing.signingDigestHex, 'hex');
  const genesisSig = Buffer.from(secp.signMessageHashSchnorr(privateKey, digest));
  if (genesisSig.length !== 64) throw new Error('bad genesis sig');
  const finalized = await finalizeChipnetGenesisTransaction(genesisReq, genesisSig.toString('hex'));

  if (opts.broadcast) {
    const genAccept = rpc.backend === 'layer1-ssh'
      ? bchnTestMempool(finalized.transactionHex)
      : await rpc.testmempoolaccept(finalized.transactionHex);
    if (!genAccept?.[0]?.allowed) throw new Error(`genesis rejected: ${JSON.stringify(genAccept)}`);
    if (rpc.backend === 'layer1-ssh') bchnSendHex(finalized.transactionHex);
    else await rpc.sendrawtransaction(finalized.transactionHex);
  }

  const instance = {
    schema: 'shieldkit/pool-instance/v1',
    role: 'custom',
    network: opts.network || 'chipnet',
    profileId: built.profileId,
    instanceId: built.instanceId,
    bundleDirectory: 'bundle',
    unlockPinLens: PIN_LENS,
    createdAt: new Date().toISOString(),
    mode: 'with-genesis',
    categoryTxid,
    genesisTxid: finalized.transactionId,
    broadcast: !!opts.broadcast,
    // Capacity is immutable at genesis (live anonymity set ceiling).
    denominationSatoshis: capacity.denominationSatoshis,
    reserveCapSatoshis: capacity.reserveCapSatoshis,
    maxNotes: capacity.maxNotes,
    maxLiveNotes: capacity.maxLiveNotes,
    capacity: capacitySummary(capacity),
  };
  writeFileSync(path.join(out, 'instance.json'), JSON.stringify(instance, null, 2));
  writeFileSync(path.join(out, 'state.json'), JSON.stringify({
    stateTxid: finalized.transactionId,
    feeUtxos: change > 1000n
      ? [{ txid: categoryTxid, vout: 1, sats: Number(change) }]
      : [],
    history: [],
    capacity: {
      maxLiveNotes: capacity.maxLiveNotes,
      reserveCapSatoshis: capacity.reserveCapSatoshis,
      denominationSatoshis: capacity.denominationSatoshis,
    },
  }, null, 2));
  writeFileSync(path.join(out, '01-category-fund.json'), JSON.stringify({
    categoryTxid, categoryVout: 0, categorySats: categorySats.toString(), change: change.toString(),
    fundHex, broadcast: !!opts.broadcast,
  }, null, 2));
  writeFileSync(path.join(out, '03-genesis-tx.json'), JSON.stringify({
    transactionId: finalized.transactionId,
    transactionHex: finalized.transactionHex,
    measurements: finalized.measurements,
    broadcast: !!opts.broadcast,
  }, null, 2));

  return {
    instance,
    built,
    categoryTxid,
    genesisTxid: finalized.transactionId,
    broadcast: !!opts.broadcast,
    capacity,
  };
}

async function main() {
  const out = path.resolve(arg('out', path.join(ROOT, '.cache/my-pool')));
  const unlockRoot = resolveUnlockRoot();
  const leanRoot = resolveLeanRoot();
  const networkArg = arg('network', 'chipnet');
  if (networkArg !== 'chipnet' && networkArg !== 'mainnet') {
    throw new Error('--network must be chipnet|mainnet');
  }
  const network = networkArg;

  if (hasFlag('with-genesis')) {
    const { createChainRpc } = await import('../packages/kit/chipnet-rpc.mjs');
    const { assertBroadcastAllowed } = await import('../packages/kit/network.mjs');
    const walletsPath = arg('wallets', path.join(ROOT, '.cache/e2e-full-20260725/local-wallets.json'));
    // Protocol fee rate is fixed 1 sat/B everywhere (no rate choice).
    // Category parent value is operator choice; default is small (not a fee pad).
    // Genesis spends category → state carrier (1080) + change + exact wire-byte fee.
    const { MINIMUM_STATE_CARRIER_SATOSHIS } = await import('../packages/profile/genesis.mjs');
    const DUST_SATS = 546;
    // Conservative upper bounds on wire size for fund/genesis at 1 sat/B (actual fee = exact wire).
    const FUND_TX_WIRE_PAD = 400;
    const GENESIS_TX_WIRE_PAD = 800;
    const minCategoryForGenesis = Number(MINIMUM_STATE_CARRIER_SATOSHIS) + GENESIS_TX_WIRE_PAD + DUST_SATS;
    const categorySatsRaw = Number(arg('category-sats', String(minCategoryForGenesis)));
    if (!Number.isFinite(categorySatsRaw) || categorySatsRaw < minCategoryForGenesis) {
      throw new Error(
        `--category-sats must be ≥ ${minCategoryForGenesis} `
        + `(state carrier ${MINIMUM_STATE_CARRIER_SATOSHIS} + genesis fee pad @1 sat/B + dust)`,
      );
    }
    const categorySats = String(categorySatsRaw);
    // Fund UTXO must cover: category output + fund-tx fee (1 sat/B) + non-dust change.
    const minFund = categorySatsRaw + FUND_TX_WIRE_PAD + DUST_SATS;

    // Capacity: --max-notes N  |  --reserve-cap <sats>  |  default 16 notes (1.6 BCH)
    const capacity = arg('reserve-cap')
      ? capacityFromReserveCap(arg('reserve-cap'))
      : resolvePoolCapacity(arg('max-notes', String(DEFAULT_MAX_NOTES)));
    console.error(JSON.stringify({
      phase: 'pool-capacity',
      network,
      feeRateSatoshisPerByte: 1,
      categorySats: categorySatsRaw,
      minFund,
      minCategoryForGenesis,
      ...capacity,
      summary: capacitySummary(capacity),
    }));

    if (hasFlag('broadcast')) {
      assertBroadcastAllowed({
        network,
        setupMode: 'development-only',
        mainnetAcknowledged: hasFlag('i-understand-mainnet'),
        allowDevelopmentOnMainnet: hasFlag('allow-development-on-mainnet'),
      });
    }

    const rpc = await createChainRpc({ network });
    console.error(JSON.stringify({ phase: 'rpc', backend: rpc.backend, label: rpc.label, network }));

    let fundTxid = arg('fund-txid');
    let fundVout = arg('fund-vout', '1');
    let fundMeta = null;

    if (!fundTxid || hasFlag('scan-fund')) {
      if (!existsSync(path.resolve(walletsPath))) {
        throw new Error(`--scan-fund / missing --fund-txid requires --wallets (${walletsPath})`);
      }
      const wallets = JSON.parse(readFileSync(path.resolve(walletsPath), 'utf8'));
      const addr = wallets.hot?.address;
      if (!addr) throw new Error('wallets.hot.address missing for --scan-fund');
      fundMeta = await pickVerifiedFund(rpc, addr, minFund, wallets.hot?.lockingBytecodeHex);
      fundTxid = fundMeta.txid;
      fundVout = String(fundMeta.vout);
      console.error(JSON.stringify({
        phase: 'scan-fund',
        address: addr,
        minFund,
        ...fundMeta,
      }));
    } else {
      // Explicit fund: re-verify when gettxout available; else require --fund-sats with electrum.
      let sats = arg('fund-sats') ? Number(arg('fund-sats')) : null;
      if (sats == null) {
        const utxo = rpc.backend === 'layer1-ssh'
          ? bchnGetTxOut(fundTxid, Number(fundVout))
          : await rpc.gettxout(fundTxid, Number(fundVout));
        if (!utxo || utxo._partial) {
          throw new Error(
            `funding UTXO missing/spent ${fundTxid}:${fundVout} `
            + `(gettxout null/partial — try --scan-fund or --fund-sats)`,
          );
        }
        sats = Math.round(Number(utxo.value) * 1e8);
      }
      if (sats < minFund) {
        throw new Error(`funding UTXO too small: ${sats} < ${minFund} (need category+change)`);
      }
      fundMeta = { txid: fundTxid, vout: Number(fundVout), sats, verified: true };
    }

    const result = await withGenesis(out, {
      wallets: walletsPath,
      fundTxid,
      fundVout,
      fundSats: fundMeta.sats,
      categorySats,
      capacity,
      network,
      rpc,
      pinArtifacts: arg('pin-artifacts', DEFAULT_PIN_ART),
      broadcast: hasFlag('broadcast'),
    });
    console.log(JSON.stringify({
      ok: true,
      mode: 'with-genesis',
      network,
      out,
      profileId: result.built.profileId,
      instanceId: result.built.instanceId,
      categoryTxid: result.categoryTxid,
      genesisTxid: result.genesisTxid,
      fund: fundMeta,
      capacity: result.capacity,
      anonymity: {
        maxLiveNotes: result.capacity.maxLiveNotes,
        note: `Fill the pool with up to ${result.capacity.maxLiveNotes} deposits before a withdraw for a non-trivial live set`,
      },
      broadcast: result.broadcast,
      unlockRoot,
      leanRoot,
      pinLens: PIN_LENS,
      mainnetNote: network === 'mainnet'
        ? 'Unaudited WIP; development-only pins need --allow-development-on-mainnet for broadcast; not production privacy'
        : undefined,
    }, null, 2));
    return;
  }

  const bundleSrc = path.resolve(arg('bundle', DEFAULT_PIN_BUNDLE));
  const { instance, tip } = await scaffoldOnly(out, bundleSrc);
  console.log(JSON.stringify({
    ok: true,
    mode: 'scaffold',
    out,
    profileId: instance.profileId,
    instanceId: instance.instanceId,
    stateTxid: tip,
    unlockRoot,
    leanRoot,
    pinLens: PIN_LENS,
    next: tip
      ? 'npm run shieldkit -- doctor --pool ' + out
      : 'npm run create-pool -- --out <new> --with-genesis --fund-txid … --broadcast',
  }, null, 2));
}

main().catch((e) => {
  console.error('FAIL', e.message || e);
  if (e.stack) console.error(e.stack.split('\n').slice(0, 12).join('\n'));
  process.exit(1);
});
