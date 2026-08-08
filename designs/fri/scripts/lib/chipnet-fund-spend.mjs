/**
 * Live Chipnet fund (N P2SH32 locks) + multi-input spend for a sound settlement assembly.
 * Fee: 1 sat/byte + 1. First try only. Full txids.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { encodeTransaction, hexToBin, binToHex } from '@bitauth/libauth';
import {
  buildSignedSettlement,
  SETTLEMENT_PRODUCTION_VERIFIERS,
  PLACEHOLDER_SETTLEMENT,
  MAX_TX_BYTES,
  MAX_UNLOCK_BYTES,
} from '../../packages/settlement/settlement.mjs';

const DEFAULT_SSH = process.env.CHIPNET_SSH || 'layer1-node';
const BITCOIN_CLI =
  'sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf';
const DEFAULT_WALLET =
  process.env.CHIPNET_WALLET_PRIVATE ||
  '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-private.json';
const DEFAULT_HOT =
  process.env.CHIPNET_HOT_ADDR || 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';

/** Dust per lock so 19*dust covers ~100KB spend fee + ≥546 sat output. */
export const DUST_PER_LOCK = 5288n;

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

export function rpcStdin(method, params = [], timeout = 180_000, sshHost = DEFAULT_SSH) {
  const body =
    params.map((p) => (typeof p === 'string' ? p : JSON.stringify(p))).join('\n') + '\n';
  const remote = `${BITCOIN_CLI} -stdin ${method}`;
  const r = spawnSync(
    'ssh',
    ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', sshHost, remote],
    {
      encoding: 'utf8',
      timeout,
      maxBuffer: 64 * 1024 * 1024,
      input: body,
    },
  );
  const lines = (r.stdout || '')
    .split('\n')
    .filter(
      (l) =>
        l.trim() &&
        !l.includes('SHA256:') &&
        !l.startsWith('+--') &&
        !l.startsWith('|') &&
        !l.includes('Host key fingerprint'),
    );
  const text = lines.join('\n').trim();
  let parsed = text;
  try {
    parsed = JSON.parse(text);
  } catch {
    /* bare string */
  }
  return {
    status: r.status,
    ok: r.status === 0,
    text,
    parsed,
    stderr: r.stderr || '',
  };
}

export function sshCli(rpcArgs, timeout = 120_000, sshHost = DEFAULT_SSH) {
  const remote = `${BITCOIN_CLI} ${rpcArgs}`;
  const r = spawnSync(
    'ssh',
    ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', sshHost, remote],
    { encoding: 'utf8', timeout, maxBuffer: 32 * 1024 * 1024 },
  );
  const lines = (r.stdout || '')
    .split('\n')
    .filter(
      (l) =>
        l.trim() &&
        !l.includes('SHA256:') &&
        !l.startsWith('+--') &&
        !l.startsWith('|') &&
        !l.includes('Host key fingerprint'),
    );
  return {
    status: r.status,
    ok: r.status === 0,
    stdout: lines.join('\n').trim(),
    stderr: r.stderr || '',
  };
}

export function scantxoutsetHot(addr = DEFAULT_HOT, sshHost = DEFAULT_SSH) {
  // ZERO-CONF POLICY (2026-08-07): the funding view MUST include mempool outputs.
  // scantxoutset covers only the CONFIRMED UTXO set, so a just-created UTXO would be
  // invisible and every fresh fund would force a confirmation wait. We never wait for
  // confirmations: decode the node mempool and include outputs paying `addr`.
  // Remote bash needs real backslash-quotes around the JSON string; bare `\"` in a
  // template literal collapses and leaves addr(...) unquoted → syntax error near '('.
  const raw = sshCli(`scantxoutset start "[\\"addr(${addr})\\"]"`, 300_000, sshHost);
  let scan = null;
  try {
    scan = JSON.parse(raw.stdout);
  } catch {
    /* */
  }
  const confirmed = scan?.unspents || [];
  const seen = new Set(confirmed.map((u) => `${u.txid}:${u.vout}`));
  let mempool = [];
  try {
    const mp = sshCli('getrawmempool', 60_000, sshHost);
    const txids = JSON.parse(mp.stdout);
    for (const txid of (Array.isArray(txids) ? txids : []).slice(0, 200)) {
      const txRaw = sshCli(`getrawtransaction ${txid} false`, 60_000, sshHost);
      if (!txRaw.ok) continue;
      let decoded = null;
      try {
        decoded = JSON.parse(sshCli(`decoderawtransaction ${txRaw.stdout.trim()}`, 60_000, sshHost).stdout);
      } catch {
        continue;
      }
      for (let vout = 0; vout < (decoded.vout || []).length; vout += 1) {
        const out = decoded.vout[vout];
        const pays =
          (out?.scriptPubKey?.addresses && out.scriptPubKey.addresses.includes(addr)) ||
          (out?.scriptPubKey?.address === addr);
        if (pays) {
          const key = `${txid}:${vout}`;
          if (!seen.has(key)) {
            seen.add(key);
            mempool.push({
              txid,
              vout,
              amount: Number(out.value),
              scriptPubKey: out.scriptPubKey.hex,
              confirmations: 0,
              mempool: true,
            });
          }
        }
      }
    }
  } catch {
    /* mempool scan is best-effort; confirmed view still returned */
  }
  const unspents = [...confirmed, ...mempool];
  return { raw, scan, unspents, confirmedCount: confirmed.length, mempoolCount: mempool.length };
}
export function fundAndSpendKind(opts) {
  const {
    kind,
    artifactPath,
    outDir,
    excludeOutpoints = new Set(),
    // Hot wallet is typically ~0.01–0.10 BCH class UTXOs; fund need is ~200k sats
    // (19*5288 dust + ~100KB spend fee). Keep a 1M floor for comfortable change.
    minVinSats = 1_000_000n,
    walletPath = DEFAULT_WALLET,
    sshHost = DEFAULT_SSH,
    dustPerLock = DUST_PER_LOCK,
  } = opts;

  mkdirSync(outDir, { recursive: true });

  if (!SETTLEMENT_PRODUCTION_VERIFIERS || PLACEHOLDER_SETTLEMENT) {
    return {
      ok: false,
      kind,
      note: 'product path not production / still PLACEHOLDER — refuse broadcast',
    };
  }

  const settlement = buildSignedSettlement({
    statement: { kind },
    assemblyArtifact: artifactPath,
    skipAssemble: true,
  });

  if (settlement.placeholder || !settlement.productionVerifiers) {
    return {
      ok: false,
      kind,
      note: 'assembly is placeholder / not production',
      placeholder: settlement.placeholder,
      productionVerifiers: settlement.productionVerifiers,
    };
  }

  const locks = settlement.lockingHexes;
  const unlocks = settlement.verifierUnlockingHex;
  const n = locks.length;
  if (n < 10 || unlocks.length !== n) {
    return {
      ok: false,
      kind,
      note: `bad lock/unlock counts locks=${locks.length} unlocks=${unlocks.length}`,
    };
  }

  const txBytes = settlement.vm?.txBytes ?? settlement.sizes?.txBytesMeasured ?? null;
  const maxUnlock = settlement.sizes?.maxUnlockBytes ?? null;
  if (txBytes != null && txBytes > MAX_TX_BYTES) {
    return { ok: false, kind, note: `txBytes ${txBytes} > ${MAX_TX_BYTES}` };
  }
  if (maxUnlock != null && maxUnlock > MAX_UNLOCK_BYTES) {
    return { ok: false, kind, note: `maxUnlock ${maxUnlock} > ${MAX_UNLOCK_BYTES}` };
  }
  if (settlement.vm && settlement.vm.allAccept !== true) {
    return { ok: false, kind, note: 'vm.allAccept !== true' };
  }

  const wallet = JSON.parse(readFileSync(walletPath, 'utf8'));
  const { scan, unspents } = scantxoutsetHot(wallet.address || DEFAULT_HOT, sshHost);
  if (!scan?.success) {
    return { ok: false, kind, note: 'scantxoutset failed', scan };
  }

  const ranked = unspents
    .map((u) => ({
      txid: u.txid,
      vout: u.vout,
      amount: BigInt(Math.round(Number(u.amount) * 1e8)),
      scriptPubKey: u.scriptPubKey,
      // scantxoutset / mempool may already tag CashTokens — never fee-fund from them
      hasToken: !!(u.tokenData || u.token),
      key: `${u.txid}:${u.vout}`,
    }))
    .filter(
      (u) =>
        u.amount >= minVinSats &&
        !excludeOutpoints.has(u.key) &&
        !u.hasToken,
    )
    .sort((a, b) => Number(b.amount - a.amount));

  // Prefer plain UTXOs not spent in mempool (gettxout include_mempool=true → null if busy).
  // Skip CashToken-bearing outs: signraw needs matching tokenData and they are not fee fuel.
  let vin = null;
  for (const cand of ranked.slice(0, 80)) {
    const g = rpcStdin('gettxout', [cand.txid, cand.vout, true], 30_000, sshHost);
    if (
      g.parsed &&
      typeof g.parsed === 'object' &&
      g.parsed.value != null &&
      !g.parsed.tokenData
    ) {
      vin = {
        ...cand,
        scriptPubKey: g.parsed.scriptPubKey?.hex || cand.scriptPubKey,
        amount: BigInt(Math.round(Number(g.parsed.value) * 1e8)),
      };
      break;
    }
  }

  if (!vin) {
    return {
      ok: false,
      kind,
      note: `no clean plain (non-token) hot UTXO ≥ ${minVinSats} sats (mempool-conflict free) excluding ${excludeOutpoints.size} outpoints; ranked=${ranked.length}`,
    };
  }
  const spendBytesEst = Number(txBytes || 99900);
  const feeSpendEst = BigInt(spendBytesEst + 1);
  const totalDust = dustPerLock * BigInt(n);
  if (totalDust < feeSpendEst + 546n) {
    return {
      ok: false,
      kind,
      note: `dust total ${totalDust} < fee+dustOut ${feeSpendEst + 546n}`,
    };
  }

  const fundSizeEst = 40 + n * 43 + 34 + 110; // rough; refined after encode
  let fundFee = BigInt(fundSizeEst + 1);
  let change = vin.amount - totalDust - fundFee;
  if (change < 546n) {
    return { ok: false, kind, note: `change ${change} dust` };
  }

  const fundTx = {
    version: 2,
    inputs: [
      {
        outpointTransactionHash: hexToBin(vin.txid),
        outpointIndex: vin.vout,
        sequenceNumber: 0xfffffffe,
        unlockingBytecode: new Uint8Array(0),
      },
    ],
    outputs: [
      ...locks.map((h) => ({
        lockingBytecode: hexToBin(h),
        valueSatoshis: dustPerLock,
      })),
      {
        lockingBytecode: hexToBin(wallet.lockingBytecodeHex),
        valueSatoshis: change,
      },
    ],
    locktime: 0,
  };

  let unsignedHex = binToHex(encodeTransaction(fundTx));
  fundFee = BigInt(unsignedHex.length / 2 + 110 + 1);
  change = vin.amount - totalDust - fundFee;
  if (change < 546n) {
    return { ok: false, kind, note: `change after size est ${change} dust` };
  }
  fundTx.outputs[fundTx.outputs.length - 1].valueSatoshis = change;
  unsignedHex = binToHex(encodeTransaction(fundTx));

  const wif = hexToWif(wallet.privateKeyHex, true);
  const prev = [
    {
      txid: vin.txid,
      vout: vin.vout,
      scriptPubKey: vin.scriptPubKey,
      amount: Number(vin.amount) / 1e8,
    },
  ];

  const signR = rpcStdin(
    'signrawtransactionwithkey',
    [unsignedHex, [wif], prev],
    60_000,
    sshHost,
  );
  let signed = signR.parsed;
  if (!signed?.complete || !signed?.hex) {
    return {
      ok: false,
      kind,
      note: `fund sign failed: ${JSON.stringify(signed?.errors || signed || signR.text).slice(0, 600)}`,
      fundingVin: { txid: vin.txid, vout: vin.vout, amountSats: vin.amount.toString() },
    };
  }

  // Exact fund fee = size+1
  let fundHex = signed.hex;
  const signedFundBytes = fundHex.length / 2;
  const exactFundFee = BigInt(signedFundBytes + 1);
  const changeExact = vin.amount - totalDust - exactFundFee;
  if (changeExact !== change && changeExact >= 546n) {
    fundTx.outputs[fundTx.outputs.length - 1].valueSatoshis = changeExact;
    unsignedHex = binToHex(encodeTransaction(fundTx));
    const signR2 = rpcStdin(
      'signrawtransactionwithkey',
      [unsignedHex, [wif], prev],
      60_000,
      sshHost,
    );
    if (!signR2.parsed?.complete || !signR2.parsed?.hex) {
      return { ok: false, kind, note: 'fund re-sign failed' };
    }
    fundHex = signR2.parsed.hex;
  }

  const acceptFund = rpcStdin('testmempoolaccept', [[fundHex]], 60_000, sshHost);
  const fundAllowed =
    Array.isArray(acceptFund.parsed) && acceptFund.parsed[0]?.allowed === true;
  if (!fundAllowed) {
    return {
      ok: false,
      kind,
      note: `fund testmempoolaccept rejected: ${JSON.stringify(acceptFund.parsed || acceptFund.text).slice(0, 800)}`,
      testmempoolacceptFund: acceptFund.parsed,
      fundingVin: { txid: vin.txid, vout: vin.vout },
    };
  }

  const fundTxid = String(rpcStdin('sendrawtransaction', [fundHex], 60_000, sshHost).parsed).trim();
  if (!/^[0-9a-f]{64}$/i.test(fundTxid)) {
    return { ok: false, kind, note: `bad fund txid: ${fundTxid}` };
  }
  const fundRaw = String(
    rpcStdin('getrawtransaction', [fundTxid, false], 60_000, sshHost).parsed,
  )
    .trim()
    .toLowerCase();
  if (fundRaw !== fundHex.toLowerCase()) {
    return {
      ok: false,
      kind,
      fundTxid,
      note: 'fund raw readback mismatch',
    };
  }

  // Spend: n verifier inputs → single P2PKH to hot
  let spendBytes = spendBytesEst;
  let feeExact = BigInt(spendBytes + 1);
  let outExact = totalDust - feeExact;
  if (outExact < 546n) {
    return { ok: false, kind, fundTxid, note: `spend out ${outExact} dust` };
  }

  const spendTx = {
    version: 2,
    inputs: locks.map((_, i) => ({
      outpointTransactionHash: hexToBin(fundTxid),
      outpointIndex: i,
      sequenceNumber: 0xffffffff,
      unlockingBytecode: hexToBin(unlocks[i]),
    })),
    outputs: [
      {
        lockingBytecode: hexToBin(wallet.lockingBytecodeHex),
        valueSatoshis: outExact,
      },
    ],
    locktime: 0,
  };

  let spendHex = binToHex(encodeTransaction(spendTx));
  spendBytes = spendHex.length / 2;
  feeExact = BigInt(spendBytes + 1);
  outExact = totalDust - feeExact;
  if (outExact < 546n) {
    return { ok: false, kind, fundTxid, note: `outExact ${outExact} dust after measure` };
  }
  spendTx.outputs[0].valueSatoshis = outExact;
  spendHex = binToHex(encodeTransaction(spendTx));
  spendBytes = spendHex.length / 2;
  // final fee exact
  feeExact = BigInt(spendBytes + 1);
  if (totalDust - feeExact !== spendTx.outputs[0].valueSatoshis) {
    spendTx.outputs[0].valueSatoshis = totalDust - feeExact;
    spendHex = binToHex(encodeTransaction(spendTx));
    spendBytes = spendHex.length / 2;
  }

  writeFileSync(path.join(outDir, `fund-${kind}.hex`), fundHex + '\n');
  writeFileSync(path.join(outDir, `spend-${kind}.hex`), spendHex + '\n');

  const acceptSpend = rpcStdin('testmempoolaccept', [[spendHex]], 120_000, sshHost);
  const spendAllowed =
    Array.isArray(acceptSpend.parsed) && acceptSpend.parsed[0]?.allowed === true;
  if (!spendAllowed) {
    const result = {
      ok: false,
      kind,
      fundTxid,
      spendBytes,
      feeSats: spendBytes + 1,
      feePolicy: '1_sat_per_byte_plus_1',
      dustPerLock: Number(dustPerLock),
      nInputs: n,
      testmempoolaccept: acceptSpend.parsed,
      productionVerifiers: true,
      placeholder: false,
      note: `spend testmempoolaccept rejected (first try, stop): ${JSON.stringify(acceptSpend.parsed || acceptSpend.text).slice(0, 1000)}`,
      fundingVin: { txid: vin.txid, vout: vin.vout, amountSats: vin.amount.toString() },
      sizes: { txBytes, maxUnlock },
    };
    writeFileSync(
      path.join(outDir, `CHIPNET_${kind.toUpperCase()}.json`),
      JSON.stringify(result, null, 2) + '\n',
    );
    return result;
  }

  const spendTxid = String(
    rpcStdin('sendrawtransaction', [spendHex], 120_000, sshHost).parsed,
  ).trim();
  if (!/^[0-9a-f]{64}$/i.test(spendTxid)) {
    return {
      ok: false,
      kind,
      fundTxid,
      note: `bad spend txid: ${spendTxid}`,
    };
  }
  const spendRaw = String(
    rpcStdin('getrawtransaction', [spendTxid, false], 60_000, sshHost).parsed,
  )
    .trim()
    .toLowerCase();
  const rawMatch = spendRaw === spendHex.toLowerCase();

  const result = {
    ok: rawMatch,
    kind,
    fundTxid,
    spendTxid,
    spendBytes,
    feeSats: spendBytes + 1,
    feePolicy: '1_sat_per_byte_plus_1',
    dustPerLock: Number(dustPerLock),
    nInputs: n,
    testmempoolaccept: acceptSpend.parsed,
    rawMatch,
    productionVerifiers: true,
    placeholder: false,
    fundingVin: { txid: vin.txid, vout: vin.vout, amountSats: vin.amount.toString() },
    sizes: { txBytes, maxUnlock, allAccept: settlement.vm?.allAccept },
    vendorPin: settlement.vendorPin,
    friParams: settlement.friParams,
    statement: settlement.statement,
    note: rawMatch
      ? `live Chipnet multi-input FRI ${kind} settlement admitted; exact raw match`
      : 'broadcast ok but raw mismatch',
  };

  writeFileSync(
    path.join(outDir, `CHIPNET_${kind.toUpperCase()}.json`),
    JSON.stringify(result, null, 2) + '\n',
  );
  return result;
}
