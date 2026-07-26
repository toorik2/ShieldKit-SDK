#!/usr/bin/env node
/**
 * Probe chain access. Default network: chipnet.
 *   node rpc-probe.mjs
 *   node rpc-probe.mjs --network mainnet
 * Average users: no bitcoind — public Fulcrum (Electrum TLS).
 */
import {
  createChainRpc,
  PUBLIC_CHIPNET_ELECTRUM,
  PUBLIC_MAINNET_ELECTRUM,
} from '../packages/kit/chipnet-rpc.mjs';

const i = process.argv.indexOf('--network');
const network = (i >= 0 ? process.argv[i + 1] : 'chipnet') === 'mainnet' ? 'mainnet' : 'chipnet';

const rpc = await createChainRpc({ network });
const height = await rpc.getblockcount();
const audience = rpc.backend === 'electrum' && !process.env.SHIELDKIT_ELECTRUM && !process.env.SHIELDKIT_RPC_URL
  ? 'average-user-default-public-fulcrum'
  : rpc.backend === 'jsonrpc'
    ? 'power-user-jsonrpc'
    : rpc.backend === 'layer1-ssh'
      ? 'lab-ssh'
      : 'custom-electrum';

const defaults = network === 'mainnet' ? PUBLIC_MAINNET_ELECTRUM : PUBLIC_CHIPNET_ELECTRUM;

console.log(JSON.stringify({
  ok: true,
  network,
  audience,
  note: 'Average users do not need bitcoind. Public Fulcrum is enough for tip/fees/broadcast.',
  backend: rpc.backend,
  label: rpc.label,
  height,
  publicElectrumDefaults: defaults.map((e) => `${e.host}:${e.port}`),
  env: {
    SHIELDKIT_RPC_URL: Boolean(process.env.SHIELDKIT_RPC_URL || process.env.BCH_RPC_URL),
    SHIELDKIT_ELECTRUM: process.env.SHIELDKIT_ELECTRUM || null,
  },
}, null, 2));
