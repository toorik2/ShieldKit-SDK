/**
 * Real Groth16 prove/verify for PoolActionV2Direct (dev setup).
 */
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import * as snarkjs from 'snarkjs';
import { actionPacketPublicLimbsV2, decodeActionPacketV2 } from '../packet.mjs';
import { buildExpandedCircuitInput, CIRCUIT_TREE_DEPTH } from './witness.mjs';

export class V2ProveError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2ProveError';
  }
}

const fail = (m) => {
  throw new V2ProveError(m);
};

/**
 * Build circuit witness input from a V2 action packet + optional expanded note/path.
 * Backward-compatible: if no note/path, uses counter-only fields (legacy small circuit).
 */
export function buildCircuitInputFromPacket(packetBytes, expanded) {
  if (expanded?.note && expanded?.path) {
    return buildExpandedCircuitInput({
      packetBytes,
      note: expanded.note,
      path: expanded.path,
      nullifierInsert: expanded.nullifierInsert,
      encryption: expanded.encryption,
      recordCommitmentHex: expanded.recordCommitmentHex,
      preNoteRoot: expanded.preNoteRoot,
      postNoteRoot: expanded.postNoteRoot,
      preNullifierRoot: expanded.preNullifierRoot,
      postNullifierRoot: expanded.postNullifierRoot,
    });
  }
  // Legacy minimal input (old 35-constraint circuit)
  const decoded = decodeActionPacketV2(packetBytes);
  const limbs = actionPacketPublicLimbsV2(packetBytes);
  const kindCode = decoded.kind === 'deposit' ? 1 : decoded.kind === 'transfer' ? 2 : 3;
  return {
    publicInput0: limbs[0],
    publicInput1: limbs[1],
    limb0: limbs[0],
    limb1: limbs[1],
    kind: String(kindCode),
    preNoteCount: decoded.preState.noteCount,
    preNullifierCount: decoded.preState.nullifierCount,
    preReserve: decoded.preState.reserveSats,
    preActionSequence: decoded.preState.actionSequence,
    preMaximumLiveNotes: decoded.preState.maximumLiveNotes,
    postNoteCount: decoded.postState.noteCount,
    postNullifierCount: decoded.postState.nullifierCount,
    postReserve: decoded.postState.reserveSats,
    postActionSequence: decoded.postState.actionSequence,
  };
}

export async function proveActionV2({
  packetBytes,
  zkeyPath,
  wasmPath,
  expanded,
}) {
  if (!zkeyPath || !wasmPath) fail('zkeyPath and wasmPath required');
  if (!existsSync(zkeyPath) || !existsSync(wasmPath)) fail('circuit artifacts missing');
  const input = buildCircuitInputFromPacket(packetBytes, expanded);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return Object.freeze({
    proof,
    publicSignals,
    input,
    publicInputs: Object.freeze([input.publicInput0, input.publicInput1]),
  });
}

export async function verifyActionV2({
  proof,
  publicSignals,
  verificationKeyPath,
}) {
  const vkey = JSON.parse(readFileSync(verificationKeyPath, 'utf8'));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  if (!ok) fail('Groth16 verification failed');
  return true;
}

export function loadSetupPaths(artifactDir) {
  const manifest = JSON.parse(readFileSync(path.join(artifactDir, 'manifest.json'), 'utf8'));
  return Object.freeze({
    zkey: path.join(artifactDir, manifest.artifacts.zkey),
    wasm: path.join(artifactDir, manifest.artifacts.wasm),
    verificationKey: path.join(artifactDir, manifest.artifacts.verificationKey),
    manifest,
  });
}

export { CIRCUIT_TREE_DEPTH, buildExpandedCircuitInput };
