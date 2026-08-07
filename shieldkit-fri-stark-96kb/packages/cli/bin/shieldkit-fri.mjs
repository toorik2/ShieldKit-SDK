#!/usr/bin/env node
/**
 * shieldkit-fri — Chipnet-only FRI-STARK product CLI (beta).
 */
import { createHash } from 'node:crypto';
import { productionFriParams, friParamId } from '../../prove/fri-params.mjs';
import { genesisState, encodeState, STATE_BYTES } from '../../core/codecs/state.mjs';
import { PACKET_BYTES } from '../../core/codecs/packet.mjs';

const args = process.argv.slice(2);
const cmd = args[0] || 'help';

function help() {
  console.log(`shieldkit-fri — ShieldKit FRI-STARK beta (Chipnet only)

Commands:
  help              Show this help
  version           Package version
  params            Show production FRI params + friParamId
  wires             Print normative wire sizes
  doctor            Local self-checks (params + wires)
  create-pool-local Offline profile + SFS1 genesis state (no broadcast)
  production-status  Publication readiness gates (evidence/production)

Mainnet is refused by default. Normative plan: FRI_STARK_REPLACEMENT_PLAN.md
Live Chipnet create-pool: npm run story:chipnet-create-pool
`);
}

if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
  help();
  process.exit(0);
}

if (cmd === 'version' || cmd === '--version') {
  console.log('shieldkit-fri-stark@0.1.0-beta.1');
  process.exit(0);
}

if (cmd === 'params') {
  const p = productionFriParams();
  console.log(JSON.stringify({ ...p, friParamId: friParamId(p) }, null, 2));
  process.exit(0);
}

if (cmd === 'wires') {
  console.log(JSON.stringify({ SFS1: STATE_BYTES, SFP1: PACKET_BYTES, nftCommitment: 'SFS1 bytes' }, null, 2));
  process.exit(0);
}

if (cmd === 'doctor') {
  const p = productionFriParams();
  const profileId = createHash('sha256').update('doctor').digest('hex');
  const g = genesisState({ profileId });
  const buf = encodeState(g);
  console.log(JSON.stringify({
    ok: buf.length === 128,
    friParamId: friParamId(p),
    sfs1: buf.length,
    sfp1: PACKET_BYTES,
  }, null, 2));
  process.exit(buf.length === 128 ? 0 : 1);
}

if (cmd === 'create-pool-local') {
  const { createPoolLocal } = await import('../../pool/create-pool.mjs');
  const r = createPoolLocal({ network: 'chipnet' });
  console.log(JSON.stringify({
    ok: r.stateBytes.length === 128,
    profileId: r.profileId,
    state: r.state,
    stateHex: r.stateHex,
    manifest: r.manifest,
  }, null, 2));
  process.exit(r.stateBytes.length === 128 ? 0 : 1);
}

if (cmd === 'production-status') {
  const { readFileSync, existsSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const path = await import('node:path');
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
  const p = path.join(root, 'evidence/production/PRODUCTION_REPORT.json');
  if (!existsSync(p)) {
    console.log(JSON.stringify({ ok: false, publicationReady: false, error: 'missing PRODUCTION_REPORT.json' }, null, 2));
    process.exit(2);
  }
  const r = JSON.parse(readFileSync(p, 'utf8'));
  console.log(JSON.stringify({
    ok: r.ok === true,
    publicationReady: r.publicationReady === true,
    blockers: r.blockers,
    gates: r.gates,
    locks: { ok: r.locks?.ok, drifts: r.locks?.drifts },
  }, null, 2));
  process.exit(r.publicationReady ? 0 : 2);
}

console.error(`unknown command: ${cmd}`);
help();
process.exit(2);
