#!/usr/bin/env node
/**
 * Probe Chipnet chain access.
 * Average users: no bitcoind required — public Fulcrum (Electrum TLS) is the default.
 */
import { createChipnetRpc, PUBLIC_CHIPNET_ELECTRUM } from '../packages/kit/chipnet-rpc.mjs';

const rpc = await createChipnetRpc();
const height = await rpc.getblockcount();
const audience = rpc.backend === 'electrum' && !process.env.SHIELDKIT_ELECTRUM && !process.env.SHIELDKIT_RPC_URL
  ? 'average-user-default-public-fulcrum'
  : rpc.backend === 'jsonrpc'
    ? 'power-user-jsonrpc'
    : rpc.backend === 'layer1-ssh'
      ? 'lab-ssh'
      : 'custom-electrum';

console.log(JSON.stringify({
  ok: true,
  audience,
  note: 'Average users do not need bitcoind or free public JSON-RPC. Public Fulcrum is enough for tip/fees/broadcast.',
  backend: rpc.backend,
  label: rpc.label,
  height,
  publicElectrumDefaults: PUBLIC_CHIPNET_ELECTRUM.map((e) => `${e.host}:${e.port}`),
  env: {
    SHIELDKIT_RPC_URL: Boolean(process.env.SHIELDKIT_RPC_URL || process.env.BCH_RPC_URL),
    SHIELDKIT_ELECTRUM: process.env.SHIELDKIT_ELECTRUM || null,
  },
}, null, 2));
