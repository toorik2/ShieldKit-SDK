#!/usr/bin/env node
/** Probe Chipnet RPC fallbacks (public Electrum / env / lab). */
import { createChipnetRpc, PUBLIC_CHIPNET_ELECTRUM } from '../packages/kit/chipnet-rpc.mjs';

const rpc = await createChipnetRpc();
const height = await rpc.getblockcount();
console.log(JSON.stringify({
  ok: true,
  backend: rpc.backend,
  label: rpc.label,
  height,
  publicElectrum: PUBLIC_CHIPNET_ELECTRUM.map((e) => `${e.host}:${e.port}`),
  env: {
    SHIELDKIT_RPC_URL: Boolean(process.env.SHIELDKIT_RPC_URL || process.env.BCH_RPC_URL),
    SHIELDKIT_ELECTRUM: process.env.SHIELDKIT_ELECTRUM || null,
  },
}, null, 2));
