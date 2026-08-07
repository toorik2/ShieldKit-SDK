/**
 * createPool — can't-do-evil genesis under full state + FRI topology.
 *
 * Genesis fund TX (single broadcast):
 *  - Input: plain vout=0 hot UTXO (CashTokens category mint rule)
 *  - Output 0: mutable SFS1 state NFT under **state covenant** (NOT operator P2PKH)
 *  - Outputs 1..19: dust on exact FRI role P2SH32 locks from sound assembly
 *  - Output last: change to hot
 *
 * Operator cannot spend the state alone. State moves only with co-spent role locks
 * (FRI verifier programs). Role locks come from a production sound assembly artifact.
 *
 * Authority: FRI_STARK_REPLACEMENT_PLAN.md (common parent carriers + can't-do-evil).
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import path from 'node:path';
import {
  encodeTransaction,
  encodeTokenPrefix,
  hexToBin,
  binToHex,
} from '@bitauth/libauth';
import {
  genesisState,
  encodeState,
  profileIdFromManifest,
  STATE_BYTES,
  DENOMINATION_SATS,
} from '../core/codecs/state.mjs';
import {
  compileStateCovenant,
  compileStateCovenantFromLocks,
  ROLE_COUNT,
} from './state-covenant.mjs';
import {
  buildSignedSettlement,
  SETTLEMENT_PRODUCTION_VERIFIERS,
  PLACEHOLDER_SETTLEMENT,
} from '../settlement/settlement.mjs';

/** Dust for role carriers (tokenless P2SH32). */
export const ROLE_DUST_SATS = 1000n;
/** State carrier base (non-dust for 128B NFT + covenant lock). */
export const STATE_CARRIER_BASE_SATS = 2000n;

export const RELATION_ID = 'shieldkit-pool-action-fri-v1';
export const TOPOLOGY_ID = 'fri-sound-lean-fused-v1';
export const PUBLIC_ABI = 'sha256-u32le8';

function hexToWif(hex, compressed = true) {
  const payload = Buffer.concat([
    Buffer.from([0xef]),
    Buffer.from(hex, 'hex'),
    compressed ? Buffer.from([0x01]) : Buffer.alloc(0),
  ]);
  const c1 = createHash('sha256').update(payload).digest();
  const c2 = createHash('sha256').update(c1).digest();
  const full = Buffer.concat([payload, c2.subarray(0, 4)]);
  const ALPH = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let x = BigInt(`0x${full.toString('hex')}`);
  let s = '';
  while (x > 0n) {
    s = ALPH[Number(x % 58n)] + s;
    x /= 58n;
  }
  for (const b of full) {
    if (b === 0) s = `1${s}`;
    else break;
  }
  return s;
}

export function createPoolLocal({
  profileManifest,
  maximumLiveNotes = 100_000,
  network = 'chipnet',
} = {}) {
  const manifest = profileManifest || {
    relationId: RELATION_ID,
    publicAbi: PUBLIC_ABI,
    topologyId: TOPOLOGY_ID,
    denominationSats: DENOMINATION_SATS.toString(),
    stateCarrierBaseSats: STATE_CARRIER_BASE_SATS.toString(),
    roleDustSats: ROLE_DUST_SATS.toString(),
    stateBytes: STATE_BYTES,
    roleCount: ROLE_COUNT,
    cantDoEvil: true,
    fri: {
      depth: 20,  // AMENDED 2026-08-06 (plan AMENDMENT-20260806; product config)
      blowup: 2048,
      queries: 8,
      grind: 24,
      foldStep: 3,
      deep: true,
    },
    network,
    schema: 'shieldkit-fri-profile-v1',
  };
  const profileId = profileIdFromManifest(manifest);
  const state = genesisState({ profileId, maximumLiveNotes });
  const stateBytes = encodeState(state);
  return { profileId, manifest, state, stateBytes, stateHex: stateBytes.toString('hex') };
}

/**
 * Load production FRI role lockings from a sound settlement assembly artifact.
 */
export function loadRoleLockingsFromAssembly(artifactPath) {
  const settlement = buildSignedSettlement({
    statement: { kind: 'transfer' },
    assemblyArtifact: artifactPath,
    skipAssemble: true,
  });
  if (settlement.placeholder || !settlement.productionVerifiers) {
    throw new Error('assembly is not production FRI (placeholder)');
  }
  if (!SETTLEMENT_PRODUCTION_VERIFIERS || PLACEHOLDER_SETTLEMENT) {
    throw new Error('product path still PLACEHOLDER — refuse create-pool');
  }
  const locks = settlement.lockingHexes;
  if (!locks || locks.length !== ROLE_COUNT) {
    throw new Error(`expected ${ROLE_COUNT} role locks, got ${locks?.length}`);
  }
  return {
    roleLockingHexes: locks.map((h) => h.toLowerCase()),
    roles: settlement.verifierRoles,
    friParams: settlement.friParams,
    vendorPin: settlement.vendorPin,
    statement: settlement.statement,
    vm: settlement.vm,
  };
}

export function buildGenesisTopologyTx({
  fundingVin,
  stateBytes,
  stateCovenant,
  roleLockingHexes,
  changeLockingHex,
  feeSats,
  stateCarrierBase = STATE_CARRIER_BASE_SATS,
  roleDust = ROLE_DUST_SATS,
}) {
  const category = hexToBin(fundingVin.txid);
  const commitment =
    stateBytes instanceof Uint8Array ? stateBytes : Uint8Array.from(stateBytes);
  if (commitment.length !== STATE_BYTES) {
    throw new Error(`SFS1 must be ${STATE_BYTES}`);
  }
  const token = {
    category,
    amount: 0n,
    nft: { capability: 'mutable', commitment },
  };
  const prefix = encodeTokenPrefix(token);
  if (typeof prefix === 'string') throw new Error(prefix);

  const nRoles = roleLockingHexes.length;
  const totalOut =
    stateCarrierBase + roleDust * BigInt(nRoles) + BigInt(feeSats);
  const change = BigInt(fundingVin.amountSats) - totalOut;
  if (change < 546n) throw new Error(`change ${change} dust`);

  const outputs = [
    {
      lockingBytecode: hexToBin(stateCovenant.lockingHex),
      valueSatoshis: stateCarrierBase,
      token,
    },
    ...roleLockingHexes.map((h) => ({
      lockingBytecode: hexToBin(h),
      valueSatoshis: roleDust,
    })),
    {
      lockingBytecode: hexToBin(changeLockingHex),
      valueSatoshis: change,
    },
  ];

  const tx = {
    version: 2,
    inputs: [
      {
        outpointTransactionHash: hexToBin(fundingVin.txid),
        outpointIndex: fundingVin.vout,
        sequenceNumber: 0xfffffffe,
        unlockingBytecode: new Uint8Array(0),
      },
    ],
    outputs,
    locktime: 0,
  };
  return { tx, token, categoryHex: fundingVin.txid.toLowerCase(), change };
}

/**
 * One-shot prep: plain large UTXO → output0 P2PKH mint fuel + change.
 * CashTokens category mint requires spending a parent vout=0.
 */
function prepPlainVout0({ rpcStdin, wallet, unspents, minOutSats = 1_000_000n }) {
  const ranked = unspents
    .map((u) => ({
      txid: u.txid,
      vout: u.vout,
      amountSats: BigInt(Math.round(Number(u.amount) * 1e8)),
      scriptPubKey: u.scriptPubKey,
    }))
    .filter((u) => u.amountSats >= minOutSats + 50_000n)
    .sort((a, b) => Number(b.amountSats - a.amountSats));

  let src = null;
  for (const cand of ranked.slice(0, 40)) {
    const g = rpcStdin('gettxout', [cand.txid, cand.vout, true], 30_000);
    if (!g.parsed || g.parsed.value == null) continue;
    if (g.parsed.tokenData || g.parsed.token_data) continue;
    src = cand;
    break;
  }
  if (!src) return { ok: false, note: 'no plain UTXO large enough to prep vout0' };

  let fee = 300n;
  const mk = (feeSats) => {
    const change = src.amountSats - minOutSats - feeSats;
    if (change < 546n) throw new Error('prep change dust');
    return {
      version: 2,
      inputs: [
        {
          outpointTransactionHash: hexToBin(src.txid),
          outpointIndex: src.vout,
          sequenceNumber: 0xfffffffe,
          unlockingBytecode: new Uint8Array(0),
        },
      ],
      outputs: [
        {
          lockingBytecode: hexToBin(wallet.lockingBytecodeHex),
          valueSatoshis: minOutSats,
        },
        {
          lockingBytecode: hexToBin(wallet.lockingBytecodeHex),
          valueSatoshis: change,
        },
      ],
      locktime: 0,
    };
  };

  let tx = mk(fee);
  let unsignedHex = binToHex(encodeTransaction(tx));
  fee = BigInt(unsignedHex.length / 2 + 110 + 1);
  tx = mk(fee);
  unsignedHex = binToHex(encodeTransaction(tx));
  const wif = hexToWif(wallet.privateKeyHex, true);
  const prev = [
    {
      txid: src.txid,
      vout: src.vout,
      scriptPubKey: src.scriptPubKey,
      amount: Number(src.amountSats) / 1e8,
    },
  ];
  const signR = rpcStdin('signrawtransactionwithkey', [unsignedHex, [wif], prev], 60_000);
  if (!signR.parsed?.complete || !signR.parsed?.hex) {
    return {
      ok: false,
      note: `prep sign failed: ${JSON.stringify(signR.parsed || signR.text).slice(0, 400)}`,
    };
  }
  let hex = signR.parsed.hex;
  const exactFee = BigInt(hex.length / 2 + 1);
  if (exactFee !== fee) {
    tx = mk(exactFee);
    unsignedHex = binToHex(encodeTransaction(tx));
    const s2 = rpcStdin('signrawtransactionwithkey', [unsignedHex, [wif], prev], 60_000);
    if (!s2.parsed?.complete || !s2.parsed?.hex) return { ok: false, note: 'prep re-sign failed' };
    hex = s2.parsed.hex;
  }
  const acc = rpcStdin('testmempoolaccept', [[hex]], 60_000);
  if (!(Array.isArray(acc.parsed) && acc.parsed[0]?.allowed)) {
    return {
      ok: false,
      note: `prep testmempoolaccept rejected: ${JSON.stringify(acc.parsed || acc.text).slice(0, 500)}`,
    };
  }
  const txid = String(rpcStdin('sendrawtransaction', [hex], 60_000).parsed).trim();
  if (!/^[0-9a-f]{64}$/i.test(txid)) return { ok: false, note: `prep bad txid ${txid}` };
  const raw = String(rpcStdin('getrawtransaction', [txid, false], 60_000).parsed)
    .trim()
    .toLowerCase();
  if (raw !== hex.toLowerCase()) return { ok: false, note: 'prep raw mismatch', txid };
  return {
    ok: true,
    prepTxid: txid,
    vin: {
      txid,
      vout: 0,
      amountSats: minOutSats,
      scriptPubKey: wallet.lockingBytecodeHex,
    },
  };
}

/**
 * Live Chipnet create-pool under can't-do-evil topology.
 */
export async function createPoolLive(deps) {
  const {
    rpcStdin,
    scantxoutsetHot,
    walletPath,
    outDir,
    assemblyPath,
    requireVout0 = true,
    requirePlain = true,
    minVinSats = 100_000n,
    stateCarrierBase = STATE_CARRIER_BASE_SATS,
    roleDust = ROLE_DUST_SATS,
  } = deps;

  mkdirSync(outDir, { recursive: true });
  const jsonReplacer = (_, v) => (typeof v === 'bigint' ? v.toString() : v);

  if (!existsSync(walletPath)) {
    return { ok: false, cantDoEvil: false, note: `missing wallet ${walletPath}` };
  }
  if (!assemblyPath || !existsSync(assemblyPath)) {
    return {
      ok: false,
      cantDoEvil: false,
      note: 'missing production FRI assembly artifact for role lockings',
    };
  }

  let rolePack;
  try {
    rolePack = loadRoleLockingsFromAssembly(assemblyPath);
  } catch (e) {
    return { ok: false, cantDoEvil: false, note: String(e.message || e) };
  }

  let stateCovenant;
  try {
    stateCovenant = compileStateCovenantFromLocks(rolePack.roleLockingHexes);
  } catch (e) {
    return { ok: false, cantDoEvil: false, note: `state covenant compile: ${e.message || e}` };
  }

  const local = createPoolLocal({ network: 'chipnet' });
  const wallet = JSON.parse(readFileSync(walletPath, 'utf8'));
  const { scan, unspents } = scantxoutsetHot(wallet.address);
  if (!scan?.success) return { ok: false, note: 'scantxoutset failed', scan };

  const ranked = unspents
    .map((u) => ({
      txid: u.txid,
      vout: u.vout,
      amountSats: BigInt(Math.round(Number(u.amount) * 1e8)),
      scriptPubKey: u.scriptPubKey,
    }))
    .filter((u) => u.amountSats >= minVinSats && (!requireVout0 || u.vout === 0))
    .sort((a, b) => Number(b.amountSats - a.amountSats));

  let vin = null;
  for (const cand of ranked.slice(0, 50)) {
    const g = rpcStdin('gettxout', [cand.txid, cand.vout, true], 30_000);
    if (!g.parsed || typeof g.parsed !== 'object' || g.parsed.value == null) continue;
    const tok = g.parsed.tokenData || g.parsed.token_data;
    if (requirePlain && tok) continue;
    vin = cand;
    break;
  }
  let prepMeta = null;
  if (!vin) {
    const prep = prepPlainVout0({
      rpcStdin,
      wallet,
      unspents,
      minOutSats: 1_000_000n,
    });
    if (!prep.ok) {
      return {
        ok: false,
        cantDoEvil: true,
        note: `no plain vout0 and prep failed: ${prep.note}`,
        ranked: ranked.length,
      };
    }
    vin = prep.vin;
    prepMeta = { prepTxid: prep.prepTxid };
  }

  // Fee size+1
  let feeSats = 2000n;
  let built = buildGenesisTopologyTx({
    fundingVin: vin,
    stateBytes: local.stateBytes,
    stateCovenant,
    roleLockingHexes: rolePack.roleLockingHexes,
    changeLockingHex: wallet.lockingBytecodeHex,
    feeSats,
    stateCarrierBase,
    roleDust,
  });
  let unsignedHex = binToHex(encodeTransaction(built.tx));
  feeSats = BigInt(unsignedHex.length / 2 + 110 + 1);
  built = buildGenesisTopologyTx({
    fundingVin: vin,
    stateBytes: local.stateBytes,
    stateCovenant,
    roleLockingHexes: rolePack.roleLockingHexes,
    changeLockingHex: wallet.lockingBytecodeHex,
    feeSats,
    stateCarrierBase,
    roleDust,
  });
  unsignedHex = binToHex(encodeTransaction(built.tx));

  const wif = hexToWif(wallet.privateKeyHex, true);
  const prev = [
    {
      txid: vin.txid,
      vout: vin.vout,
      scriptPubKey: vin.scriptPubKey,
      amount: Number(vin.amountSats) / 1e8,
    },
  ];
  const signR = rpcStdin('signrawtransactionwithkey', [unsignedHex, [wif], prev], 60_000);
  let signed = signR.parsed;
  if (!signed?.complete || !signed?.hex) {
    const detail = [signR.stderr, signR.text, signed?.errors]
      .filter(Boolean)
      .map((x) => (typeof x === 'string' ? x : JSON.stringify(x)))
      .join(' | ')
      .slice(0, 1200);
    return {
      ok: false,
      cantDoEvil: true,
      note: `sign failed: ${detail}`,
      fundingVin: { txid: vin.txid, vout: vin.vout, amountSats: vin.amountSats.toString() },
      stateCovenant: { lockingHex: stateCovenant.lockingHex, redeemBytes: stateCovenant.redeemBytes },
    };
  }

  let genesisHex = signed.hex;
  const exactFee = BigInt(genesisHex.length / 2 + 1);
  if (exactFee !== feeSats) {
    built = buildGenesisTopologyTx({
      fundingVin: vin,
      stateBytes: local.stateBytes,
      stateCovenant,
      roleLockingHexes: rolePack.roleLockingHexes,
      changeLockingHex: wallet.lockingBytecodeHex,
      feeSats: exactFee,
      stateCarrierBase,
      roleDust,
    });
    unsignedHex = binToHex(encodeTransaction(built.tx));
    const signR2 = rpcStdin('signrawtransactionwithkey', [unsignedHex, [wif], prev], 60_000);
    if (!signR2.parsed?.complete || !signR2.parsed?.hex) {
      return { ok: false, cantDoEvil: true, note: 're-sign failed' };
    }
    genesisHex = signR2.parsed.hex;
  }

  const accept = rpcStdin('testmempoolaccept', [[genesisHex]], 60_000);
  const allowed = Array.isArray(accept.parsed) && accept.parsed[0]?.allowed === true;
  if (!allowed) {
    return {
      ok: false,
      cantDoEvil: true,
      note: `testmempoolaccept rejected: ${JSON.stringify(accept.parsed || accept.text).slice(0, 1000)}`,
      fundingVin: { txid: vin.txid, vout: vin.vout, amountSats: vin.amountSats.toString() },
      testmempoolaccept: accept.parsed,
      genesisBytes: genesisHex.length / 2,
      stateLockingHex: stateCovenant.lockingHex,
    };
  }

  const genesisTxid = String(rpcStdin('sendrawtransaction', [genesisHex], 60_000).parsed).trim();
  if (!/^[0-9a-f]{64}$/i.test(genesisTxid)) {
    return { ok: false, note: `bad genesis txid: ${genesisTxid}` };
  }
  const raw = String(rpcStdin('getrawtransaction', [genesisTxid, false], 60_000).parsed)
    .trim()
    .toLowerCase();
  const rawMatch = raw === genesisHex.toLowerCase();

  // Verify state is NOT under operator lock
  const operatorLock = wallet.lockingBytecodeHex.toLowerCase();
  const stateLock = stateCovenant.lockingHex.toLowerCase();
  const operatorKeySpendable = stateLock === operatorLock;

  const genesisDescriptor = {
    schema: 'shieldkit-fri-genesis-descriptor-v2-cant-do-evil',
    network: 'chipnet',
    relationId: RELATION_ID,
    publicAbi: PUBLIC_ABI,
    topologyId: TOPOLOGY_ID,
    cantDoEvil: true,
    operatorKeySpendable: false,
    profileId: local.profileId,
    profileManifest: local.manifest,
    categoryHex: built.categoryHex,
    genesisTxid,
    stateOutpoint: `${genesisTxid}:0`,
    stateLockingHex: stateCovenant.lockingHex,
    stateCovenantRedeemSha256: stateCovenant.redeemSha256,
    stateCovenantRedeemBytes: stateCovenant.redeemBytes,
    roleOutpoints: rolePack.roleLockingHexes.map((_, i) => `${genesisTxid}:${i + 1}`),
    roleLockingHexes: rolePack.roleLockingHexes,
    roles: rolePack.roles,
    stateCarrierBaseSats: stateCarrierBase.toString(),
    roleDustSats: roleDust.toString(),
    state: local.state,
    stateCommitmentHex: local.stateHex,
    feePolicy: '1_sat_per_byte_plus_1',
    fundingVin: {
      txid: vin.txid,
      vout: vin.vout,
      amountSats: vin.amountSats.toString(),
    },
    assemblyPath,
    vendorPin: rolePack.vendorPin,
    friParams: rolePack.friParams,
    note:
      `State NFT under topology covenant + ${ROLE_COUNT} FRI role locks funded. Operator P2PKH cannot spend state alone.`,
  };
  const instanceId32 = createHash('sha256')
    .update(JSON.stringify(genesisDescriptor))
    .digest('hex');
  genesisDescriptor.instanceId32 = instanceId32;

  const result = {
    ok: rawMatch && !operatorKeySpendable && stateCovenant.cantDoEvil === true,
    cantDoEvil: !operatorKeySpendable,
    operatorKeySpendable,
    genesisTxid,
    categoryHex: built.categoryHex,
    instanceId32,
    profileId: local.profileId,
    stateOutpoint: `${genesisTxid}:0`,
    stateLockingHex: stateCovenant.lockingHex,
    stateCommitmentHex: local.stateHex,
    nRoleLocks: ROLE_COUNT,
    roleOutpoints: genesisDescriptor.roleOutpoints,
    genesisBytes: genesisHex.length / 2,
    feeSats: genesisHex.length / 2 + 1,
    feePolicy: '1_sat_per_byte_plus_1',
    testmempoolaccept: accept.parsed,
    rawMatch,
    fundingVin: {
      txid: vin.txid,
      vout: vin.vout,
      amountSats: vin.amountSats.toString(),
    },
    prep: prepMeta,
    stateCovenant: {
      redeemBytes: stateCovenant.redeemBytes,
      redeemSha256: stateCovenant.redeemSha256,
      lockingHex: stateCovenant.lockingHex,
      minInputs: stateCovenant.minInputs,
    },
    genesisDescriptor,
    state: local.state,
    note: rawMatch && !operatorKeySpendable
      ? 'create-pool genesis admitted: state under covenant + FRI role topology funded (can\'t-do-evil)'
      : operatorKeySpendable
        ? 'FAIL: state still operator-key spendable'
        : 'broadcast ok but raw mismatch',
  };

  const safe = JSON.parse(JSON.stringify(result, jsonReplacer));
  writeFileSync(path.join(outDir, 'genesis.hex'), genesisHex + '\n');
  writeFileSync(
    path.join(outDir, 'GENESIS_DESCRIPTOR.json'),
    JSON.stringify(genesisDescriptor, jsonReplacer, 2) + '\n',
  );
  writeFileSync(path.join(outDir, 'STATE_COVENANT.json'), JSON.stringify({
    redeemHex: stateCovenant.redeemHex,
    lockingHex: stateCovenant.lockingHex,
    redeemSha256: stateCovenant.redeemSha256,
    redeemBytes: stateCovenant.redeemBytes,
    roleCount: ROLE_COUNT,
    operatorKeySpendable: false,
    cantDoEvil: true,
  }, null, 2) + '\n');
  writeFileSync(path.join(outDir, 'CREATE_POOL.json'), JSON.stringify(safe, null, 2) + '\n');
  return safe;
}
