#!/usr/bin/env node
/**
 * Offline passive-observer linkability check on a pool's settlement log.
 * Uses the shipped SCAR decoder only — no reimplementation of packet layout.
 *
 * Usage:
 *   node 03-create-your-own-pool/scripts/analyze-packet-linkability.mjs --pool <pool-dir>
 *   node 03-create-your-own-pool/scripts/analyze-packet-linkability.mjs --packet <752-byte-file> [--deposit-cm <hex64>]
 */
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { decodeActionPacket } from '../packages/action/packet.mjs';

const ZERO = '0'.repeat(64);

function arg(name, fallback = undefined) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return fallback;
  return process.argv[i + 1] ?? fallback;
}

function extractPackets(hex) {
  const buf = Buffer.from(hex, 'hex');
  const out = [];
  for (let i = 0; i < buf.length - 755; i += 1) {
    if (buf[i] === 0x4d && buf[i + 1] === 0xf0 && buf[i + 2] === 0x02) {
      try {
        out.push(decodeActionPacket(buf.subarray(i + 3, i + 3 + 752)));
      } catch {
        // skip non-canonical or unrelated 752-byte windows
      }
    }
  }
  return out;
}

function analyzePackets(packets) {
  const deposits = packets.filter((p) => p.kind === 'deposit');
  const spends = packets.filter((p) => p.kind === 'transfer' || p.kind === 'withdrawal');
  const links = spends.map((s) => {
    const matched = deposits.filter((d) => d.outputCommitment === s.inputCommitment);
    return {
      spendKind: s.kind,
      spendSeq: s.postState.actionSequence,
      preLive: s.preState.liveNoteCount,
      inputCommitment: s.inputCommitment,
      inputNullifier: s.inputNullifier,
      outputCommitment: s.outputCommitment,
      matchedDepositOutputCommitments: matched.map((d) => d.outputCommitment),
      equalityLinkable: matched.length > 0,
      inputCommitmentIsZero: s.inputCommitment === ZERO,
    };
  });
  let verdict = 'NO_SPEND';
  if (spends.length > 0) {
    if (links.every((l) => l.equalityLinkable)) verdict = 'LINKABLE_BY_EQUALITY';
    else if (links.every((l) => l.inputCommitmentIsZero || !l.equalityLinkable)) {
      verdict = 'NOT_LINKABLE_BY_EQUALITY';
    } else verdict = 'MIXED';
  }
  return {
    depositCount: deposits.length,
    spendCount: spends.length,
    deposits: deposits.map((d) => ({
      seq: d.postState.actionSequence,
      outputCommitment: d.outputCommitment,
    })),
    links,
    verdict,
  };
}

function main() {
  const pool = arg('pool');
  const packetPath = arg('packet');
  if (pool) {
    const statePath = path.join(path.resolve(pool), 'state.json');
    if (!existsSync(statePath)) {
      console.error(JSON.stringify({ ok: false, error: `missing ${statePath}` }));
      process.exit(1);
    }
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    const settles = state.settlementLog?.settles || [];
    const packets = [];
    for (const s of settles) {
      const hex = typeof s === 'string' ? s : s?.hex;
      if (hex) packets.push(...extractPackets(hex));
    }
    const analysis = analyzePackets(packets);
    console.log(JSON.stringify({ ok: true, pool: path.resolve(pool), settleCount: settles.length, ...analysis }, null, 2));
    return;
  }
  if (packetPath) {
    const raw = readFileSync(path.resolve(packetPath));
    const bytes = raw.length === 752 ? raw : Buffer.from(raw.toString().trim(), 'hex');
    const decoded = decodeActionPacket(bytes);
    const depositCm = arg('deposit-cm');
    const report = {
      ok: true,
      kind: decoded.kind,
      inputCommitment: decoded.inputCommitment,
      outputCommitment: decoded.outputCommitment,
      inputNullifier: decoded.inputNullifier,
      inputCommitmentIsZero: decoded.inputCommitment === ZERO,
    };
    if (depositCm) {
      report.depositOutputCommitment = depositCm;
      report.equalityLinkable = depositCm === decoded.inputCommitment;
    }
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  console.error('Usage: --pool <dir> | --packet <file> [--deposit-cm <hex64>]');
  process.exit(2);
}

main();
