/**
 * densFuel PF7 unlock build for V2 Direct (CLI + live scripts).
 *
 * HARD RULE (global ops): first try only — no multi-retry / re-prove loops.
 *
 * Before prove: bind pin-compatible `transactionContextHash` so public limbs
 * sit in the live ECIP envelope (nfail ≤ C7_MAXTRY=2). That is deterministic
 * witness construction (option 3), not densFuel retry.
 *
 * Then: prove once + densFuel unlock once. On failure, stop and fix root cause.
 */
import {
  mkdirSync, writeFileSync, copyFileSync, readFileSync,
} from 'node:fs';
import path from 'node:path';
import { proveActionV2, verifyActionV2 } from '../prove/prove.mjs';
import { adaptSnarkjsGroth16, sha256File } from '../../prove/groth16.mjs';
import { buildVerifierUnlocks } from '../../unlock-builder/index.mjs';
import { resolveCircuitArtifacts } from './prove-local.mjs';
import { bindPinCompatibleTransactionContext } from './pin-compatible-witness.mjs';

const N_VERIFIERS = 7;
const SOURCE_VALUE = BigInt(process.env.C7_SOURCE_VALUE_SATS || '10000');

export class DensfuelBuildError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'DensfuelBuildError';
    if (cause) this.cause = cause;
  }
}

function snarkjsProofJson(proof) {
  return {
    protocol: 'groth16',
    curve: 'bn128',
    pi_a: proof.pi_a,
    pi_b: proof.pi_b,
    pi_c: proof.pi_c,
  };
}

/**
 * Bind pin-compatible packet (if enabled), prove once, densFuel unlock once.
 *
 * @returns {{
 *   proved, result, densLocks: Buffer[], densUnlocks: Buffer[], workDir,
 *   attempt: 0, packetBytes: Buffer, pinBind: object|null
 * }}
 */
export async function buildDensfuelForPacket({
  packetBytes,
  expanded,
  workDir,
  maxAttempts = 1,
  // Default: run offline ECIP gate (fixed Point identity via measureEcipNfailFromAffine).
  // Set V2_SKIP_ECIP_GATE=1 only for explicit lab isolation.
  skipEcipGate = process.env.V2_SKIP_ECIP_GATE === '1',
  // Default: bind pin-compatible transactionContextHash before prove.
  pinBind = process.env.V2_PIN_BIND !== '0',
  pinSeed,
}) {
  if (maxAttempts !== 1) {
    throw new DensfuelBuildError(
      `densFuel maxAttempts=${maxAttempts} forbidden (first-try only; fix root cause, do not retry)`,
    );
  }
  mkdirSync(workDir, { recursive: true });
  const arts = resolveCircuitArtifacts();
  process.env.C7_SOURCE_VALUE_SATS = String(SOURCE_VALUE);
  process.env.PUBLIC_BENCH_CONTEXT = process.env.PUBLIC_BENCH_CONTEXT || '1';

  let boundPacket = Buffer.from(packetBytes);
  let pinMeta = null;
  if (pinBind) {
    try {
      pinMeta = await bindPinCompatibleTransactionContext(boundPacket, {
        verificationKeyPath: arts.verificationKeyPath,
        seed: pinSeed,
      });
      boundPacket = pinMeta.packetBytes;
    } catch (e) {
      throw new DensfuelBuildError(
        `pin-compatible witness bind failed: ${e.message}`,
        e,
      );
    }
  }

  const packetPath = path.join(workDir, 'action.packet');
  writeFileSync(packetPath, boundPacket);
  if (pinMeta) {
    writeFileSync(
      path.join(workDir, 'pin-bind.json'),
      `${JSON.stringify({
        nfail: pinMeta.nfail,
        searchIndex: pinMeta.searchIndex,
        changed: pinMeta.changed,
        transactionContextHash: pinMeta.transactionContextHash,
        publicLimbs: pinMeta.publicLimbs,
      }, null, 2)}\n`,
    );
  }
  const vkeyPath = path.join(workDir, 'verification_key.json');
  copyFileSync(arts.verificationKeyPath, vkeyPath);

  // tsx IPC uses AF_UNIX sun_path (~108 bytes). Keep TMPDIR short.
  const tmpBase = process.env.V2_DENSFUEL_TMPDIR || '/home/toorik/.cache/skd';
  process.env.TMPDIR = path.join(tmpBase, `${process.pid}-${Date.now().toString(36)}`);
  mkdirSync(process.env.TMPDIR, { recursive: true });
  if (process.env.TMPDIR.length > 80) {
    throw new DensfuelBuildError(`TMPDIR too long for tsx IPC: ${process.env.TMPDIR.length} chars`);
  }

  const proved = await proveActionV2({
    packetBytes: boundPacket,
    zkeyPath: arts.zkeyPath,
    wasmPath: arts.wasmPath,
    expanded,
  });
  await verifyActionV2({
    proof: proved.proof,
    publicSignals: proved.publicSignals,
    verificationKeyPath: arts.verificationKeyPath,
  });
  const proofPath = path.join(workDir, 'proof.json');
  const publicPath = path.join(workDir, 'public.json');
  const adapterPath = path.join(workDir, 'adapter.json');
  writeFileSync(proofPath, `${JSON.stringify(snarkjsProofJson(proved.proof), null, 2)}\n`);
  writeFileSync(publicPath, `${JSON.stringify(proved.publicSignals.map(String))}\n`);
  const adapter = await adaptSnarkjsGroth16({
    verificationKey: { path: vkeyPath, sha256: await sha256File(vkeyPath) },
    proof: { path: proofPath, sha256: await sha256File(proofPath) },
    publicSignals: { path: publicPath, sha256: await sha256File(publicPath) },
  });
  writeFileSync(adapterPath, `${JSON.stringify(adapter, null, 2)}\n`);
  const unlockOut = path.join(workDir, 'unlocks');
  try {
    const res = await buildVerifierUnlocks({
      adapterPath,
      packetPath,
      outDir: unlockOut,
      requirePinLens: false,
      skipEcipGate,
      quiet: true,
    });
    const dumpPath = path.join(unlockOut, 'build/inputs_dump.json');
    const dump = JSON.parse(readFileSync(dumpPath, 'utf8'));
    if (res?.gateOk !== true) {
      throw new DensfuelBuildError(
        'densFuel gateOk false after pin-bind + single build '
          + '(unexpected — pin bind should guarantee nfail envelope; check pin/VK mismatch)',
      );
    }
    return {
      proved,
      result: res,
      densLocks: dump.slice(0, N_VERIFIERS).map((r) => Buffer.from(r.lock, 'hex')),
      densUnlocks: dump.slice(0, N_VERIFIERS).map((r) => Buffer.from(r.unlock, 'hex')),
      workDir,
      attempt: 0,
      packetBytes: boundPacket,
      // JSON-safe pin metadata (no raw Buffer)
      pinBind: pinMeta && {
        nfail: pinMeta.nfail,
        searchIndex: pinMeta.searchIndex,
        changed: pinMeta.changed,
        transactionContextHash: pinMeta.transactionContextHash,
        publicLimbs: pinMeta.publicLimbs,
      },
    };
  } catch (e) {
    throw new DensfuelBuildError(
      `densFuel single-shot failed: ${e.message}`,
      e,
    );
  }
}

export { N_VERIFIERS, SOURCE_VALUE };
