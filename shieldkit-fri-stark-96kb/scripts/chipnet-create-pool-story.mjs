#!/usr/bin/env node
/**
 * Live Chipnet e2e: create-pool under **can't-do-evil** topology.
 *
 *  - Offline profile + SFS1 genesis state
 *  - Compile state covenant pinned to 19 production FRI role P2SH32 locks
 *  - Fund common parent: state NFT@0 (covenant) + role dust@1..19
 *  - Category mint from plain vout=0; fee size+1; exact raw readback
 *  - Refuse product green if state is operator-P2PKH spendable
 *
 * Usage: node scripts/chipnet-create-pool-story.mjs
 */
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPoolLive, createPoolLocal } from '../packages/pool/create-pool.mjs';
import { compileStateCovenant } from '../packages/pool/state-covenant.mjs';
import { loadRoleLockingsFromAssembly } from '../packages/pool/create-pool.mjs';
import { rpcStdin, scantxoutsetHot, sshCli } from './lib/chipnet-fund-spend.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'evidence/create-pool');
const WALLET =
  process.env.CHIPNET_WALLET_PRIVATE ||
  '/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-wallet-019f8ed4/wallet-private.json';
const ASSEMBLY =
  process.env.SETTLEMENT_ARTIFACT ||
  // Product ROLE_COUNT=17 (nq=7); d4/b32@nq8 assemblies are 19-role and fail-closed.
  path.join(
    ROOT,
    'evidence/production/assemble-state0/assemble-transfer-d20-b2048-n7-g30-base1.materialized.json',
  );
const t0 = Date.now();
const jsonReplacer = (_, v) => (typeof v === 'bigint' ? v.toString() : v);

mkdirSync(OUT, { recursive: true });

console.error('[create-pool] can\'t-do-evil topology genesis');
console.error('[create-pool] assembly=', ASSEMBLY);

const chainRaw = sshCli('getblockchaininfo');
let chainInfo = null;
try {
  chainInfo = JSON.parse(chainRaw.stdout);
} catch {
  /* */
}
if (!chainRaw.ok || chainInfo?.chain !== 'chip') {
  console.error('[create-pool] FAIL: not live chipnet');
  process.exit(2);
}

const local = createPoolLocal({ network: 'chipnet' });
writeFileSync(
  path.join(OUT, 'LOCAL_GENESIS_STATE.json'),
  JSON.stringify(
    {
      profileId: local.profileId,
      state: local.state,
      stateHex: local.stateHex,
      manifest: local.manifest,
    },
    null,
    2,
  ) + '\n',
);

// Offline: prove covenant compiles and is not a key spend
let offlineCovenant = null;
let offlineOk = false;
try {
  if (!existsSync(ASSEMBLY)) throw new Error('missing assembly');
  const roles = loadRoleLockingsFromAssembly(ASSEMBLY);
  offlineCovenant = compileStateCovenant(roles.roleLockingHexes);
  offlineOk =
    offlineCovenant.operatorKeySpendable === false &&
    offlineCovenant.cantDoEvil === true &&
    offlineCovenant.redeemBytes > 100;
  console.error(
    '[create-pool] state covenant redeemBytes=',
    offlineCovenant.redeemBytes,
    'cantDoEvil=',
    offlineCovenant.cantDoEvil,
  );
} catch (e) {
  console.error('[create-pool] offline covenant FAIL', e.message || e);
}

const live = await createPoolLive({
  rpcStdin,
  scantxoutsetHot,
  walletPath: WALLET,
  outDir: OUT,
  assemblyPath: ASSEMBLY,
  requireVout0: true,
  requirePlain: true,
  minVinSats: 100_000n,
});

const ok =
  offlineOk &&
  live.ok === true &&
  live.cantDoEvil === true &&
  live.operatorKeySpendable === false &&
  live.rawMatch === true &&
  !!live.genesisTxid &&
  !!live.stateLockingHex;

const report = {
  schema: 'shieldkit-fri-create-pool-story-v2-cant-do-evil',
  name: 'chipnet-create-pool-e2e',
  ok,
  wallSeconds: (Date.now() - t0) / 1000,
  timestamp: new Date().toISOString(),
  policy: {
    cantDoEvil: true,
    forbidOperatorP2pkhState: true,
    requireFriRoleTopology: true,
    feePolicy: '1_sat_per_byte_plus_1',
  },
  chain: {
    chain: chainInfo.chain,
    blocks: chainInfo.blocks,
    bestblockhash: chainInfo.bestblockhash,
  },
  offline: {
    ok: offlineOk,
    profileId: local.profileId,
    state: local.state,
    covenantRedeemBytes: offlineCovenant?.redeemBytes ?? null,
    covenantSha256: offlineCovenant?.redeemSha256 ?? null,
  },
  live,
  gates: {
    liveChipnetTip: true,
    localSfs1: local.stateBytes.length === 128,
    stateCovenantCompiled: offlineOk,
    notOperatorKeySpendable: live.operatorKeySpendable === false,
    friRoleLocksFunded: (live.nRoleLocks || 0) === 17,
    testmempoolaccept: Array.isArray(live.testmempoolaccept)
      ? live.testmempoolaccept[0]?.allowed === true
      : false,
    broadcast: !!live.genesisTxid,
    exactRawReadback: !!live.rawMatch,
    cantDoEvil: live.cantDoEvil === true,
  },
  revoked: {
    operatorP2pkhGenesis: true,
    note: 'v1 operator-P2PKH state birth is forbidden under can\'t-do-evil; v2 funds state covenant + FRI roles',
  },
  note: ok
    ? 'create-pool green under can\'t-do-evil: state covenant + 17 FRI role locks on common parent'
    : live.note || 'create-pool failed fail-closed',
};

writeFileSync(
  path.join(OUT, 'CREATE_POOL_STORY_REPORT.json'),
  JSON.stringify(report, jsonReplacer, 2) + '\n',
);

console.log(
  JSON.stringify(
    {
      STORY_OK: report.ok,
      wallSeconds: report.wallSeconds,
      cantDoEvil: live.cantDoEvil,
      operatorKeySpendable: live.operatorKeySpendable,
      genesisTxid: live.genesisTxid || null,
      categoryHex: live.categoryHex || null,
      instanceId32: live.instanceId32 || null,
      stateOutpoint: live.stateOutpoint || null,
      stateLockingHex: live.stateLockingHex || null,
      nRoleLocks: live.nRoleLocks || null,
      genesisBytes: live.genesisBytes || null,
      feeSats: live.feeSats || null,
      rawMatch: live.rawMatch ?? null,
      note: report.note,
      evidence: path.relative(ROOT, path.join(OUT, 'CREATE_POOL_STORY_REPORT.json')),
    },
    jsonReplacer,
    2,
  ),
);

process.exit(ok ? 0 : 1);
