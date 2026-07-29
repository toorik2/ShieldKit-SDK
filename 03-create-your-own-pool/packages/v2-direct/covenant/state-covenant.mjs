/**
 * SKS2 state covenant — CashScript ShieldStateV2Direct (P2SH32) on densFuel N=7.
 *
 * Locks successor state NFT to the same P2SH32; advance() binds SDA2 packet
 * pre/post SKS2, values, profile, category (LE token category), and kind.
 */
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { productBindingLock } from './binding-state.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const STATE_ARTIFACT_PATH = path.join(here, 'artifacts', 'ShieldStateV2Direct.json');

const CASH_SCRIPT_CANDIDATES = [
  '/home/toorik/Projects/ZK-Proofs/shield.cash-evidence-20260723T121421Z/node_modules/cashscript/dist/index.js',
  path.resolve(here, '../../../../../node_modules/cashscript/dist/index.js'),
];

export class StateCovenantError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StateCovenantError';
  }
}

function loadArtifact() {
  if (!existsSync(STATE_ARTIFACT_PATH)) {
    throw new StateCovenantError(`artifact missing: ${STATE_ARTIFACT_PATH}`);
  }
  return JSON.parse(readFileSync(STATE_ARTIFACT_PATH, 'utf8'));
}

async function loadCashScript() {
  for (const p of CASH_SCRIPT_CANDIDATES) {
    if (!existsSync(p)) continue;
    return import(pathToFileURL(p).href);
  }
  throw new StateCovenantError(
    'cashscript package not found — install cashscript or use monorepo evidence path',
  );
}

function toBytes32(v, label) {
  const b = typeof v === 'string' ? Buffer.from(v, 'hex') : Buffer.from(v);
  if (b.length !== 32) throw new StateCovenantError(`${label} must be 32 bytes`);
  return new Uint8Array(b);
}

/**
 * @param {object} args
 * @param {Uint8Array|Buffer} [args.bindingLock]
 * @param {string|Uint8Array} args.profileId UI/big-endian 32 bytes
 * @param {string|Uint8Array} args.instanceIdCategory UI/big-endian 32 bytes (token category)
 * @param {bigint|number} [args.stateBaseSats=10000n]
 * @param {number} [args.carrierCount=7]
 */
export async function createStateCovenant({
  bindingLock = productBindingLock(),
  profileId,
  instanceIdCategory,
  stateBaseSats = 10_000n,
  carrierCount = 7,
}) {
  if (carrierCount !== 7) {
    throw new StateCovenantError('product densFuel pin requires carrierCount=7');
  }
  const artifact = loadArtifact();
  const { Contract, MockNetworkProvider } = await loadCashScript();
  const provider = new MockNetworkProvider();
  const contract = new Contract(
    artifact,
    [
      Uint8Array.from(bindingLock),
      toBytes32(profileId, 'profileId'),
      toBytes32(instanceIdCategory, 'instanceIdCategory'),
      BigInt(stateBaseSats),
      BigInt(carrierCount),
    ],
    { provider, addressType: 'p2sh32' },
  );

  const lockingBytecode = Buffer.from(
    typeof contract.lockingBytecode === 'string'
      ? contract.lockingBytecode
      : Buffer.from(contract.lockingBytecode).toString('hex'),
    'hex',
  );

  async function generateAdvanceUnlock({ transaction, sourceOutputs, inputIndex = 8 }) {
    const unlocker = contract.unlock.advance();
    const unlockingBytecode = await unlocker.generateUnlockingBytecode({
      transaction,
      sourceOutputs,
      inputIndex,
    });
    return Buffer.from(unlockingBytecode);
  }

  return Object.freeze({
    artifactName: artifact.contractName,
    fingerprint: artifact.fingerprint || null,
    lockingBytecode,
    lockingBytecodeHex: lockingBytecode.toString('hex'),
    address: contract.address,
    tokenAddress: contract.tokenAddress,
    bytesize: contract.bytesize,
    opcount: contract.opcount,
    generateAdvanceUnlock,
    contract,
  });
}

export function artifactPresent() {
  return existsSync(STATE_ARTIFACT_PATH);
}

export function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}
