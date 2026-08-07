#!/usr/bin/env node
/**
 * Live Chipnet blank-machine e2e story (honest / fail-closed).
 *
 * 1) Clean rebuild of native Rust fri-worker (blank cargo target)
 * 2) CLI doctor + production FRI params prove D/T/W (full DEEP verify, SLA)
 * 3) Live Chipnet RPC probe + hot wallet UTXO scan
 * 4) Product sound settlement (real FRI locks) — refuse PLACEHOLDER broadcast
 * 5) Live fund P2SH32 locks → multi-input spend (transfer) →
 *    testmempoolaccept → single broadcast → exact raw readback
 *
 * Fee: 1 sat/byte + 1. First try only. Full 64-char txids.
 * Dual-host P7 / create-pool journey remain non-goals for this story.
 */
import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  writeFileSync,
  existsSync,
  rmSync,
  readFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import {
  encodeTransaction,
  encodeDataPush,
  hexToBin,
  binToHex,
  flattenBinArray,
  hash256,
  encodeLockingBytecodeP2sh32,
} from '@bitauth/libauth';
import {
  buildSignedSettlement,
  materializeAssembly,
  SETTLEMENT_PRODUCTION_VERIFIERS,
  PLACEHOLDER_SETTLEMENT,
  PRODUCTION_FLOOR,
  friDomainPreflight,
  MAX_TX_BYTES,
  MAX_UNLOCK_BYTES,
} from '../packages/settlement/settlement.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'evidence/blank-machine-chipnet');
const TARGET = path.join(ROOT, '.private/cargo-target-blank-chipnet');
const WORKER = path.join(TARGET, 'release/shieldkit-fri-worker');
const CLEAN = process.env.BLANK_CLEAN !== '0';
const HOT_ADDR = process.env.CHIPNET_HOT_ADDR || 'bchtest:qq3ncrumwkf6ajcfmjs3jvvktgttjp2gcg3yujp0yv';
const SSH_HOST = process.env.CHIPNET_SSH || 'layer1-node';
const BITCOIN_CLI =
  'sudo -n -u bchn /usr/local/bin/bitcoin-cli -conf=/etc/bchn/bitcoin.conf';
const WALLET =
  process.env.CHIPNET_WALLET_PRIVATE ||
  '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-private.json';
const ART_TRANSFER =
  process.env.SETTLEMENT_ARTIFACT ||
  path.join(ROOT, 'evidence/settlement-prod/assemble-transfer-d4-b32.json');
/** Dust per lock so 19*dust covers ~100KB spend fee + ≥546 sat output. */
const DUST_PER_LOCK = 5288n;

mkdirSync(OUT, { recursive: true });
const steps = [];
const t0 = Date.now();

function logStep(entry) {
  steps.push(entry);
  const slim = {
    step: entry.step,
    ok: entry.ok,
    ms: entry.ms,
    status: entry.status,
  };
  if (entry.json) {
    slim.verifyOk = entry.json.verifyOk;
    slim.proveSeconds = entry.json.proveSeconds;
    slim.usesPython = entry.json.usesPython;
    slim.kind = entry.json.kind;
    if (entry.json.peakRssBytes != null) {
      slim.peakRssGiB =
        Math.round((entry.json.peakRssBytes / (1 << 30)) * 10000) / 10000;
    }
  }
  if (entry.note) slim.note = entry.note;
  console.log(JSON.stringify(slim));
  return entry;
}

function run(step, cmd, args, opts = {}) {
  const started = Date.now();
  const r = spawnSync(cmd, args, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, ...(opts.env || {}) },
    timeout: opts.timeout ?? 0,
  });
  let json = null;
  if (opts.parseJson && r.status === 0) {
    try {
      const lines = (r.stdout || '').trim().split('\n').filter(Boolean);
      json = JSON.parse(lines[lines.length - 1]);
    } catch {
      /* */
    }
  }
  return logStep({
    step,
    cmd: [cmd, ...args].join(' '),
    status: r.status,
    ms: Date.now() - started,
    ok: r.status === 0 && (opts.requireJson ? !!json : true),
    json,
    stdoutTail: (r.stdout || '').slice(-2500),
    stderrTail: (r.stderr || '').slice(-1500),
  });
}

/** bitcoin-cli via ssh using -stdin (avoids arg-list-too-long on ~100KB hex). */
function rpcStdin(method, params = [], timeout = 180_000) {
  const started = Date.now();
  // bitcoin-cli -stdin reads one JSON-RPC positional arg per line
  const body =
    params.map((p) => (typeof p === 'string' ? p : JSON.stringify(p))).join('\n') +
    '\n';
  const remote = `${BITCOIN_CLI} -stdin ${method}`;
  const r = spawnSync(
    'ssh',
    ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', SSH_HOST, remote],
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
    /* bare string e.g. txid */
  }
  return {
    status: r.status,
    ms: Date.now() - started,
    ok: r.status === 0,
    text,
    parsed,
    stderr: r.stderr || '',
  };
}

function sshCli(rpcArgs, timeout = 120_000) {
  const started = Date.now();
  const remote = `${BITCOIN_CLI} ${rpcArgs}`;
  const r = spawnSync(
    'ssh',
    ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', SSH_HOST, remote],
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
    ms: Date.now() - started,
    stdout: lines.join('\n').trim(),
    stderr: r.stderr || '',
    ok: r.status === 0,
  };
}

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

// ---------- story ----------
console.error('[chipnet-blank] live Chipnet blank-machine story');
console.error('[chipnet-blank] hot=', HOT_ADDR, 'ssh=', SSH_HOST);
console.error(
  '[chipnet-blank] product flags production=',
  SETTLEMENT_PRODUCTION_VERIFIERS,
  'placeholder=',
  PLACEHOLDER_SETTLEMENT,
);

if (CLEAN && existsSync(TARGET)) {
  rmSync(TARGET, { recursive: true, force: true });
}

// 0 toolchain
const probeNode = run('probe:node', 'node', ['-v']);
const probeCargo = run('probe:cargo', 'cargo', ['--version']);
const probeRustc = run('probe:rustc', 'rustc', ['--version']);

// 1 live chain
const chainRaw = sshCli('getblockchaininfo');
let chainInfo = null;
try {
  chainInfo = JSON.parse(chainRaw.stdout);
} catch {
  /* */
}
const chainStep = logStep({
  step: 'chipnet:getblockchaininfo',
  cmd: 'ssh layer1-node bitcoin-cli getblockchaininfo',
  status: chainRaw.status,
  ms: chainRaw.ms,
  ok: chainRaw.ok && chainInfo?.chain === 'chip',
  json: chainInfo
    ? {
        chain: chainInfo.chain,
        blocks: chainInfo.blocks,
        bestblockhash: chainInfo.bestblockhash,
        verificationprogress: chainInfo.verificationprogress,
      }
    : null,
  stderrTail: chainRaw.stderr.slice(0, 500),
  note: chainInfo?.chain === 'chip' ? 'live chipnet tip' : 'not chipnet or rpc fail',
});
writeFileSync(
  path.join(OUT, 'chipnet-blockchaininfo.json'),
  JSON.stringify(chainInfo || { error: chainRaw.stderr || chainRaw.stdout }, null, 2) + '\n',
);

// 2 UTXO scan hot wallet
const scanRaw = sshCli(`scantxoutset start "[\\"addr(${HOT_ADDR})\\"]"`, 300_000);
let scan = null;
try {
  scan = JSON.parse(scanRaw.stdout);
} catch {
  /* */
}
const unspents = scan?.unspents || [];
const totalAmount = scan?.total_amount ?? null;
const fundingOk =
  scan?.success === true && typeof totalAmount === 'number' && totalAmount > 0.01;
const utxoStep = logStep({
  step: 'chipnet:scantxoutset-hot',
  cmd: `scantxoutset addr(${HOT_ADDR})`,
  status: scanRaw.status,
  ms: scanRaw.ms,
  ok: fundingOk,
  json: {
    success: scan?.success,
    total_amount: totalAmount,
    utxoCount: unspents.length,
    sample: unspents.slice(0, 3).map((u) => ({
      txid: u.txid,
      vout: u.vout,
      amount: u.amount,
      height: u.height,
    })),
  },
  note: fundingOk
    ? `hot funded with ${totalAmount} tBCH across ${unspents.length} UTXOs`
    : 'hot wallet unfunded or scan failed',
});
writeFileSync(
  path.join(OUT, 'chipnet-hot-utxos.json'),
  JSON.stringify(
    {
      address: HOT_ADDR,
      success: scan?.success,
      total_amount: totalAmount,
      height: scan?.height,
      bestblock: scan?.bestblock,
      utxoCount: unspents.length,
      unspents: unspents.map((u) => ({
        txid: u.txid,
        vout: u.vout,
        amount: u.amount,
        height: u.height,
        scriptPubKey: u.scriptPubKey,
      })),
    },
    null,
    2,
  ) + '\n',
);

// 3 clean build + tests
const build = run(
  'cargo:build-release',
  'cargo',
  ['build', '-p', 'shieldkit-fri-worker', '--release'],
  { env: { CARGO_TARGET_DIR: TARGET }, timeout: 600_000 },
);
const cargoTest = run(
  'cargo:test-lib',
  'cargo',
  ['test', '-p', 'shieldkit-fri-prover', '--lib'],
  { env: { CARGO_TARGET_DIR: TARGET }, timeout: 300_000 },
);
const doctor = run('cli:doctor', 'node', ['packages/cli/bin/shieldkit-fri.mjs', 'doctor'], {
  parseJson: true,
});
const selftest = run('product:prove-selftest', 'node', ['scripts/prove-rust.mjs', 'selftest'], {
  env: { SHIELDKIT_FRI_WORKER: WORKER },
  parseJson: true,
  requireJson: true,
});

// 4 production proves (Rust SLA floor)
const kinds = ['deposit', 'transfer', 'withdrawal'];
const prod = [];
for (const kind of kinds) {
  if (!build.ok) break;
  const started = Date.now();
  const r = spawnSync(WORKER, [], {
    cwd: ROOT,
    input:
      JSON.stringify({
        cmd: 'prove',
        kind,
        depth: PRODUCTION_FLOOR.depth,
        seed: 1,
        blowup: PRODUCTION_FLOOR.blowup,
        queries: PRODUCTION_FLOOR.queries,
        grindBits: PRODUCTION_FLOOR.grind,
        foldStep: PRODUCTION_FLOOR.foldStep,
        maskDeg: 64,
        deep: true,
      }) + '\n',
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  let json = null;
  try {
    json = JSON.parse((r.stdout || '').trim());
  } catch {
    /* */
  }
  const slaOk =
    r.status === 0 &&
    json?.verifyOk === true &&
    json?.usesPython === false &&
    json?.proveSeconds <= 60 &&
    (json?.peakRssBytes || 0) <= 4 * (1 << 30);
  const entry = logStep({
    step: `product:prove-production:${kind}`,
    cmd: `worker prove ${kind} depth=20 product`,
    status: r.status,
    ms: Date.now() - started,
    ok: slaOk,
    json,
  });
  prod.push(entry);
  if (json) {
    writeFileSync(path.join(OUT, `proof-meta-${kind}.json`), JSON.stringify(json, null, 2) + '\n');
  }
}

// 5 Production floor domain fail-closed (exact on-chain floor not 8^m without pad)
const floorPre = friDomainPreflight(PRODUCTION_FLOOR);
const floorStep = logStep({
  step: 'production-floor:domain-preflight',
  cmd: 'friDomainPreflight(PRODUCTION_FLOOR)',
  status: floorPre.ok ? 0 : 4,
  ms: 0,
  ok: floorPre.ok === false, // success = correctly fail-closed for exact tuple
  json: floorPre,
  note: floorPre.reason,
});
writeFileSync(
  path.join(OUT, 'PRODUCTION_FLOOR_PREFLIGHT.json'),
  JSON.stringify({ ok: false, productionFloorGreen: false, preflight: floorPre }, null, 2) + '\n',
);

// 6 Sound settlement product path (measured-green d4/b32 artifact — real FRI locks)
let settlement = null;
let settleStep = null;
if (!existsSync(ART_TRANSFER)) {
  settleStep = logStep({
    step: 'settlement:load-artifact',
    cmd: ART_TRANSFER,
    status: 1,
    ms: 0,
    ok: false,
    note: 'missing sound assembly artifact',
  });
} else {
  const raw = JSON.parse(readFileSync(ART_TRANSFER, 'utf8'));
  const assembly = raw.roleHex ? raw : materializeAssembly(raw);
  settlement = buildSignedSettlement({
    statement: assembly.statement || { kind: 'transfer' },
    assemblyArtifact: ART_TRANSFER,
    skipAssemble: true,
  });
  const isProduct =
    settlement.productionVerifiers === true &&
    settlement.placeholder === false &&
    SETTLEMENT_PRODUCTION_VERIFIERS === true &&
    PLACEHOLDER_SETTLEMENT === false;
  const sizesOk =
    (settlement.sizes?.txBytesMeasured ?? settlement.vm?.txBytes ?? 0) <= MAX_TX_BYTES &&
    (settlement.sizes?.maxUnlockBytes ?? 0) <= MAX_UNLOCK_BYTES &&
    settlement.vm?.allAccept === true;
  settleStep = logStep({
    step: 'settlement:product-sound-transfer',
    cmd: 'buildSignedSettlement(artifact)',
    status: isProduct && sizesOk ? 0 : 1,
    ms: 0,
    ok: isProduct && sizesOk,
    note: isProduct
      ? `real FRI locks nInputs=${settlement.verifierRoles?.length} txBytes=${settlement.sizes?.txBytesMeasured ?? settlement.vm?.txBytes}`
      : 'not production sound settlement',
    json: {
      productionVerifiers: settlement.productionVerifiers,
      placeholder: settlement.placeholder,
      nRoles: settlement.verifierRoles?.length,
      txBytes: settlement.sizes?.txBytesMeasured ?? settlement.vm?.txBytes,
      maxUnlockBytes: settlement.sizes?.maxUnlockBytes,
      allAccept: settlement.vm?.allAccept,
      vendorPin: settlement.vendorPin,
    },
  });
  writeFileSync(
    path.join(OUT, 'settlement-assemble-transfer.json'),
    JSON.stringify(
      {
        productionVerifiers: settlement.productionVerifiers,
        placeholder: settlement.placeholder,
        topologyId: settlement.topologyId,
        sizes: settlement.sizes,
        vm: {
          allAccept: settlement.vm?.allAccept,
          txBytes: settlement.vm?.txBytes,
          maxUnlockBytes: settlement.vm?.maxUnlockBytes,
          txBarOk: settlement.vm?.txBarOk,
          unlockBarOk: settlement.vm?.unlockBarOk,
        },
        forge: settlement.forge,
        friParams: settlement.friParams,
        vendorPin: settlement.vendorPin,
        statement: settlement.statement,
        nRoles: settlement.verifierRoles?.length,
      },
      null,
      2,
    ) + '\n',
  );
}

// 7 Live Chipnet fund + spend (transfer only; first try)
let chipnetLive = {
  ok: false,
  fundTxid: null,
  spendTxid: null,
  spendBytes: null,
  feeSats: null,
  feePolicy: '1_sat_per_byte_plus_1',
  testmempoolaccept: null,
  rawMatch: null,
  note: null,
};

if (
  settleStep?.ok &&
  settlement &&
  !PLACEHOLDER_SETTLEMENT &&
  SETTLEMENT_PRODUCTION_VERIFIERS &&
  fundingOk &&
  existsSync(WALLET)
) {
  try {
    const wallet = JSON.parse(readFileSync(WALLET, 'utf8'));
    const locks = settlement.lockingHexes;
    const unlocks = settlement.verifierUnlockingHex;
    const n = locks.length;
    if (n < 10 || unlocks.length !== n) {
      throw new Error(`bad lock/unlock counts locks=${locks.length} unlocks=${unlocks.length}`);
    }

    // Pick clean funding UTXO (largest > 0.15 tBCH)
    const fundCandidates = unspents
      .map((u) => ({
        txid: u.txid,
        vout: u.vout,
        amount: BigInt(Math.round(Number(u.amount) * 1e8)),
        scriptPubKey: u.scriptPubKey,
      }))
      .filter((u) => u.amount > 15_000_000n)
      .sort((a, b) => Number(b.amount - a.amount));
    if (!fundCandidates.length) throw new Error('no hot UTXO > 0.15 tBCH');
    const vin = fundCandidates[0];

    // Estimate spend size from measured assembly VM size (same unlocks)
    const spendBytesEst = Number(settlement.vm?.txBytes || settlement.sizes?.txBytesMeasured || 99900);
    const feeSpend = BigInt(spendBytesEst + 1); // 1 sat/byte + 1
    const totalDust = DUST_PER_LOCK * BigInt(n);
    if (totalDust < feeSpend + 546n) {
      throw new Error(`dust total ${totalDust} < fee+dustOut ${feeSpend + 546n}`);
    }
    // Fund fee: size+1 after sign; provisional 500 sats margin then re-sign if needed
    // Build fund: n lockouts + change
    const fundFeeProv = 800n;
    const change = vin.amount - totalDust - fundFeeProv;
    if (change < 546n) throw new Error(`change ${change} dust`);

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
          valueSatoshis: DUST_PER_LOCK,
        })),
        {
          lockingBytecode: hexToBin(wallet.lockingBytecodeHex),
          valueSatoshis: change,
        },
      ],
      locktime: 0,
    };
    let unsignedHex = binToHex(encodeTransaction(fundTx));
    // Adjust change so fund fee = size+1 after signing (iterate once on unsigned size)
    const fundSizeEst = unsignedHex.length / 2 + 110; // +schnorr unlock ~106–110
    const fundFee = BigInt(fundSizeEst + 1);
    const change2 = vin.amount - totalDust - fundFee;
    if (change2 < 546n) throw new Error(`change2 ${change2} dust`);
    fundTx.outputs[fundTx.outputs.length - 1].valueSatoshis = change2;
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
    // sign via -stdin: signrawtransactionwithkey hex keys prevtxs
    const signR = rpcStdin(
      'signrawtransactionwithkey',
      [unsignedHex, [wif], prev],
      60_000,
    );
    const signed = signR.parsed;
    if (!signed?.complete || !signed?.hex) {
      throw new Error(
        `fund sign failed: ${JSON.stringify(signed?.errors || signed || signR.text).slice(0, 500)}`,
      );
    }
    // Exact fee = size+1: if change wrong by a few sats, re-adjust once
    const signedFundBytes = signed.hex.length / 2;
    const exactFundFee = BigInt(signedFundBytes + 1);
    const changeExact = vin.amount - totalDust - exactFundFee;
    let fundHex = signed.hex;
    if (changeExact !== change2 && changeExact >= 546n) {
      fundTx.outputs[fundTx.outputs.length - 1].valueSatoshis = changeExact;
      unsignedHex = binToHex(encodeTransaction(fundTx));
      const signR2 = rpcStdin(
        'signrawtransactionwithkey',
        [unsignedHex, [wif], prev],
        60_000,
      );
      if (!signR2.parsed?.complete || !signR2.parsed?.hex) {
        throw new Error('fund re-sign failed');
      }
      fundHex = signR2.parsed.hex;
    }

    const acceptFund = rpcStdin('testmempoolaccept', [[fundHex]], 60_000);
    const fundAllowed =
      Array.isArray(acceptFund.parsed) && acceptFund.parsed[0]?.allowed === true;
    if (!fundAllowed) {
      throw new Error(
        `fund testmempoolaccept rejected: ${JSON.stringify(acceptFund.parsed || acceptFund.text).slice(0, 800)}`,
      );
    }
    const fundTxid = String(rpcStdin('sendrawtransaction', [fundHex], 60_000).parsed).trim();
    if (!/^[0-9a-f]{64}$/i.test(fundTxid)) {
      throw new Error(`bad fund txid: ${fundTxid}`);
    }
    const fundRaw = String(rpcStdin('getrawtransaction', [fundTxid, false], 60_000).parsed)
      .trim()
      .toLowerCase();
    if (fundRaw !== fundHex.toLowerCase()) {
      throw new Error('fund raw readback mismatch');
    }
    logStep({
      step: 'chipnet:fund-locks',
      cmd: 'testmempoolaccept+sendrawtransaction fund',
      status: 0,
      ms: 0,
      ok: true,
      note: `fundTxid=${fundTxid} nLocks=${n} dust=${DUST_PER_LOCK}`,
    });
    chipnetLive.fundTxid = fundTxid;

    // Build multi-input spend: n verifier inputs → single P2PKH change to hot
    const spendOutValue = totalDust - feeSpend;
    if (spendOutValue < 546n) throw new Error(`spend out ${spendOutValue} < dust`);

    // Outpoint hash: libauth uses UI byte order (same as fund encode)
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
          valueSatoshis: spendOutValue,
        },
      ],
      locktime: 0,
    };
    let spendHex = binToHex(encodeTransaction(spendTx));
    let spendBytes = spendHex.length / 2;
    // Re-balance fee = spendBytes+1 (unlock sizes fixed so size stable)
    const feeExact = BigInt(spendBytes + 1);
    const outExact = totalDust - feeExact;
    if (outExact < 546n) throw new Error(`outExact ${outExact} dust`);
    if (outExact !== spendOutValue) {
      spendTx.outputs[0].valueSatoshis = outExact;
      spendHex = binToHex(encodeTransaction(spendTx));
      spendBytes = spendHex.length / 2;
    }
    if (BigInt(spendBytes + 1) !== totalDust - spendTx.outputs[0].valueSatoshis) {
      // final exact
      const f = BigInt(spendBytes + 1);
      spendTx.outputs[0].valueSatoshis = totalDust - f;
      spendHex = binToHex(encodeTransaction(spendTx));
      spendBytes = spendHex.length / 2;
    }
    writeFileSync(path.join(OUT, 'spend.hex'), spendHex + '\n');
    writeFileSync(path.join(OUT, 'fund.hex'), fundHex + '\n');

    const acceptSpend = rpcStdin('testmempoolaccept', [[spendHex]], 120_000);
    chipnetLive.testmempoolaccept = acceptSpend.parsed;
    const spendAllowed =
      Array.isArray(acceptSpend.parsed) && acceptSpend.parsed[0]?.allowed === true;
    if (!spendAllowed) {
      chipnetLive.note = `spend testmempoolaccept rejected (first try, stop): ${JSON.stringify(acceptSpend.parsed || acceptSpend.text).slice(0, 1000)}`;
      logStep({
        step: 'chipnet:spend-testmempoolaccept',
        cmd: 'testmempoolaccept spend',
        status: 1,
        ms: acceptSpend.ms,
        ok: false,
        note: chipnetLive.note,
      });
      writeFileSync(path.join(OUT, 'CHIPNET_SPEND.json'), JSON.stringify(chipnetLive, null, 2) + '\n');
    } else {
      const spendTxid = String(rpcStdin('sendrawtransaction', [spendHex], 120_000).parsed).trim();
      if (!/^[0-9a-f]{64}$/i.test(spendTxid)) {
        throw new Error(`bad spend txid: ${spendTxid}`);
      }
      const spendRaw = String(rpcStdin('getrawtransaction', [spendTxid, false], 60_000).parsed)
        .trim()
        .toLowerCase();
      const rawMatch = spendRaw === spendHex.toLowerCase();
      chipnetLive = {
        ok: rawMatch,
        fundTxid,
        spendTxid,
        spendBytes,
        feeSats: spendBytes + 1,
        feePolicy: '1_sat_per_byte_plus_1',
        dustPerLock: Number(DUST_PER_LOCK),
        nInputs: n,
        testmempoolaccept: acceptSpend.parsed,
        rawMatch,
        productionVerifiers: true,
        placeholder: false,
        kind: 'transfer',
        note: rawMatch
          ? 'live Chipnet multi-input FRI settlement admitted (mempool); exact raw match'
          : 'broadcast ok but raw mismatch',
      };
      logStep({
        step: 'chipnet:spend-broadcast',
        cmd: 'sendrawtransaction+getrawtransaction spend',
        status: rawMatch ? 0 : 1,
        ms: 0,
        ok: rawMatch,
        note: `spendTxid=${spendTxid} bytes=${spendBytes} fee=${spendBytes + 1}`,
      });
      writeFileSync(path.join(OUT, 'CHIPNET_SPEND.json'), JSON.stringify(chipnetLive, null, 2) + '\n');
      writeFileSync(
        path.join(OUT, 'CHIPNET_FUND.json'),
        JSON.stringify(
          {
            ok: true,
            fundTxid,
            nLocks: n,
            dustPerLock: Number(DUST_PER_LOCK),
            feePolicy: '1_sat_per_byte_plus_1',
            productionVerifiers: true,
            placeholder: false,
          },
          null,
          2,
        ) + '\n',
      );
    }
  } catch (e) {
    chipnetLive.note = String(e?.message || e).slice(0, 1500);
    logStep({
      step: 'chipnet:live-fund-spend',
      cmd: 'fund+spend',
      status: 1,
      ms: 0,
      ok: false,
      note: chipnetLive.note,
    });
    writeFileSync(path.join(OUT, 'CHIPNET_SPEND.json'), JSON.stringify(chipnetLive, null, 2) + '\n');
  }
} else if (PLACEHOLDER_SETTLEMENT || !SETTLEMENT_PRODUCTION_VERIFIERS) {
  logStep({
    step: 'chipnet:refuse-placeholder-broadcast',
    cmd: 'policy',
    status: 0,
    ms: 0,
    ok: true,
    note: 'PLACEHOLDER toys — refuse broadcast',
  });
} else {
  logStep({
    step: 'chipnet:live-fund-spend-skipped',
    cmd: 'skip',
    status: 1,
    ms: 0,
    ok: false,
    note: 'missing settlement product green or funding/wallet',
  });
}

// Journey checklist
const journeySteps = [
  'blank-rebuild-worker',
  'cli-doctor',
  'prove-selftest-rust',
  'prove-production-D/T/W',
  'chipnet-rpc-tip',
  'chipnet-hot-utxo-scan',
  'production-floor-fail-closed',
  'settlement-product-sound',
  'chipnet-fund-locks',
  'chipnet-spend-transfer',
  'mempool-readback-exact-raw',
  'create-pool',
  'deposit-on-chain',
  'withdraw-on-chain',
  'recover-seed-history',
  'mined-optional',
];
const completed = [
  build.ok && 'blank-rebuild-worker',
  doctor.ok && 'cli-doctor',
  selftest.ok && 'prove-selftest-rust',
  prod.length === 3 && prod.every((p) => p.ok) && 'prove-production-D/T/W',
  chainStep.ok && 'chipnet-rpc-tip',
  utxoStep.ok && 'chipnet-hot-utxo-scan',
  floorStep.ok && 'production-floor-fail-closed',
  settleStep?.ok && 'settlement-product-sound',
  chipnetLive.fundTxid && 'chipnet-fund-locks',
  chipnetLive.spendTxid && 'chipnet-spend-transfer',
  chipnetLive.rawMatch && 'mempool-readback-exact-raw',
].filter(Boolean);

const fullChipnetJourney = {
  ok: !!(chipnetLive.ok && chipnetLive.spendTxid && chipnetLive.rawMatch),
  steps: journeySteps,
  completed,
  blocked: journeySteps.filter((s) => !completed.includes(s)),
  reason: chipnetLive.ok
    ? 'Transfer settlement admitted on live Chipnet (real FRI locks). create-pool/deposit/withdraw/recover dual-host P7 still non-goals of this story.'
    : chipnetLive.note ||
      'Live multi-input spend not completed; see steps. Product path uses real FRI locks (no PLACEHOLDER).',
};

const proverOk =
  probeNode.ok &&
  probeCargo.ok &&
  probeRustc.ok &&
  build.ok &&
  cargoTest.ok &&
  doctor.ok &&
  selftest.ok &&
  selftest.json?.verifyOk === true &&
  selftest.json?.usesPython === false &&
  prod.length === 3 &&
  prod.every((p) => p.ok);

const chipnetInfraOk = chainStep.ok && utxoStep.ok;
const productSettlementOk = !!settleStep?.ok;
const storyOk =
  proverOk &&
  chipnetInfraOk &&
  productSettlementOk &&
  floorStep.ok &&
  PLACEHOLDER_SETTLEMENT === false &&
  SETTLEMENT_PRODUCTION_VERIFIERS === true &&
  chipnetLive.ok === true;

const report = {
  schema: 'shieldkit-fri-blank-machine-chipnet-story-v2',
  name: 'blank-machine-e2e-live-chipnet',
  ok: storyOk,
  fullChipnetJourney,
  wallSeconds: (Date.now() - t0) / 1000,
  host: { platform: process.platform, arch: process.arch, node: process.version },
  chipnet: {
    ssh: SSH_HOST,
    hotAddress: HOT_ADDR,
    chain: chainInfo?.chain ?? null,
    blocks: chainInfo?.blocks ?? null,
    bestblockhash: chainInfo?.bestblockhash ?? null,
    hotTotalAmount: totalAmount,
    hotUtxoCount: unspents.length,
    hotSampleOutpoints: unspents.slice(0, 5).map((u) => `${u.txid}:${u.vout}`),
    live: chipnetLive,
  },
  settlementPolicy: {
    SETTLEMENT_PRODUCTION_VERIFIERS,
    PLACEHOLDER_SETTLEMENT,
    broadcastPlaceholder: false,
    hardRule: 'never broadcast placeholder settlement on live Chipnet as product e2e',
    feePolicy: '1_sat_per_byte_plus_1',
  },
  productionFloor: {
    green: false,
    params: PRODUCTION_FLOOR,
    preflight: floorPre,
  },
  gates: {
    toolchain: probeNode.ok && probeCargo.ok && probeRustc.ok,
    cleanBuild: build.ok,
    unitTests: cargoTest.ok,
    productSelftest: selftest.ok,
    productionProvesSla: prod.length === 3 && prod.every((p) => p.ok),
    usesPython: false,
    liveChipnetTip: chainStep.ok,
    liveHotFunding: utxoStep.ok,
    productionFloorFailClosed: floorStep.ok,
    productSoundSettlement: productSettlementOk,
    liveChipnetTransferSpend: !!chipnetLive.ok,
    fullProductChipnetJourney: fullChipnetJourney.ok,
  },
  productionRows: prod.map((p) => ({
    kind: p.json?.kind,
    ok: p.ok,
    proveSeconds: p.json?.proveSeconds,
    peakRssBytes: p.json?.peakRssBytes,
    peakRssGiB:
      p.json?.peakRssBytes != null
        ? Math.round((p.json.peakRssBytes / (1 << 30)) * 10000) / 10000
        : null,
    verifyOk: p.json?.verifyOk,
    usesPython: p.json?.usesPython,
    proofBlobSha256: p.json?.proofBlobSha256,
    statement: p.json?.statement,
  })),
  workerSha256: existsSync(WORKER)
    ? createHash('sha256').update(readFileSync(WORKER)).digest('hex')
    : null,
  timestamp: new Date().toISOString(),
};

writeFileSync(path.join(OUT, 'STORY_REPORT.json'), JSON.stringify(report, null, 2) + '\n');
writeFileSync(path.join(OUT, 'STORY_STEPS.json'), JSON.stringify(steps, null, 2) + '\n');

console.log(
  JSON.stringify(
    {
      STORY_OK: report.ok,
      fullChipnetJourneyOk: fullChipnetJourney.ok,
      wallSeconds: report.wallSeconds,
      gates: report.gates,
      chipnet: {
        chain: report.chipnet.chain,
        blocks: report.chipnet.blocks,
        fundTxid: chipnetLive.fundTxid,
        spendTxid: chipnetLive.spendTxid,
        spendBytes: chipnetLive.spendBytes,
        feeSats: chipnetLive.feeSats,
        rawMatch: chipnetLive.rawMatch,
        note: chipnetLive.note,
      },
      productionRows: report.productionRows.map((r) => ({
        kind: r.kind,
        ok: r.ok,
        proveSeconds: r.proveSeconds,
        peakRssGiB: r.peakRssGiB,
      })),
      blocked: fullChipnetJourney.blocked,
      evidence: path.relative(ROOT, path.join(OUT, 'STORY_REPORT.json')),
    },
    null,
    2,
  ),
);

process.exit(storyOk ? 0 : 1);
