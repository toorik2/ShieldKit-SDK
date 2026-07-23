// Offline replacement drill for immutable verifier profiles. This module only
// authenticates supplied bundles and compares their public integration
// boundaries; it never proves, verifies a Groth16 proof, broadcasts, or opens
// a wallet.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  canonicalJson,
  deriveStateNftCategory,
  loadVerifierProfileBundle,
  parseStrictJson,
} from '../core/verifier-profile.mjs';
import { parsePf7CarrierAuthority } from '../core/pf7-authority.mjs';
import { createDesktopWalletSdk, WalletSdkError } from '../sdk/sdk.mjs';

export class ProfileReplacementDrillError extends Error {
  constructor(message) { super(message); this.name = 'ProfileReplacementDrillError'; }
}

const fail = (message) => { throw new ProfileReplacementDrillError(message); };
const HASH_ID = /^sha256:[0-9a-f]{64}$/;
const SETUP_MODES = new Set(['development-only', 'ceremony-production']);
const SDK_METHODS = Object.freeze([
  'deriveRecipientAddress', 'constructRecipientOutput', 'recoverChainOutput',
  'requireLocalProver', 'planCompletePreparation', 'preparationSigningRequest',
  'finalizeCompletePreparation', 'planWitnessBoundSettlements',
  'serializeCompleteSettlement', 'planGenesis', 'finalizeGenesis',
]);

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has missing or unknown properties`);
};
const binding = (value, label) => {
  exactKeys(value, label, ['bundleDirectory', 'expectedProfile']);
  if (typeof value.bundleDirectory !== 'string' || value.bundleDirectory.length === 0) fail(`${label}.bundleDirectory must be non-empty`);
  exactKeys(value.expectedProfile, `${label}.expectedProfile`, ['instanceId', 'network', 'profileId']);
  if (value.expectedProfile.network !== 'chipnet') fail(`${label}.expectedProfile.network must be chipnet`);
  for (const key of ['profileId', 'instanceId']) if (!HASH_ID.test(value.expectedProfile[key])) fail(`${label}.expectedProfile.${key} is invalid`);
  return value;
};
const requireEqual = (left, right, label) => { if (left !== right) fail(`replacement drill requires equal ${label}`); };
const requireDistinct = (left, right, label) => { if (left === right) fail(`replacement drill requires distinct ${label}`); };

function expectedFor(bundle) {
  return Object.freeze({ network: 'chipnet', profileId: bundle.profileId, instanceId: bundle.instanceId });
}

async function pf7Authority(bundle) {
  const artifact = bundle.manifest.artifacts.find((entry) => entry.kind === 'bch-verifier-set');
  if (artifact === undefined) fail('authenticated bundle has no bch-verifier-set artifact');
  const filename = path.resolve(bundle.root, ...artifact.path.split('/'));
  let bytes;
  try { bytes = Buffer.from(await readFile(filename)); }
  catch { fail('authenticated bch-verifier-set artifact cannot be read'); }
  if (sha256(bytes) !== artifact.sha256) fail('authenticated bch-verifier-set artifact hash drifted');
  let record;
  try { record = parseStrictJson(bytes); }
  catch { fail('authenticated bch-verifier-set artifact is not strict JSON'); }
  let authority;
  try { authority = parsePf7CarrierAuthority(record); }
  catch (error) { fail(`authenticated bch-verifier-set authority is invalid: ${error.message}`); }
  return Object.freeze({ artifact, authority });
}

function assertGenesis(bundle, label) {
  const genesis = bundle.manifest.genesis;
  if (genesis.profileId !== bundle.profileId || genesis.instanceId !== bundle.instanceId) fail(`${label} genesis identity does not match the authenticated bundle`);
  if (genesis.stateNftCategory !== deriveStateNftCategory(genesis.categoryInputOutpoint)) fail(`${label} genesis category is not derived from its category input`);
  return genesis;
}

function sdkSurface(sdk, label) {
  if (sdk.schema !== 'shield.cash/desktop-wallet-sdk/v1') fail(`${label} SDK schema changed`);
  for (const name of SDK_METHODS) if (typeof sdk[name] !== 'function') fail(`${label} SDK is missing ${name}`);
  return Object.freeze({ schema: sdk.schema, methods: SDK_METHODS });
}

/**
 * Run an offline, profile-bound replacement drill on two caller-pinned
 * bundles. A successful result proves only loader, identity, PF7 authority,
 * deterministic covenant-helper, and SDK-interface continuity. It is not
 * proof, BCH verifier VM, ceremony-security, relay, deployment, or release
 * evidence.
 */
export async function runProfileReplacementDrill(input) {
  exactKeys(input, 'replacement drill input', ['left', 'right']);
  const leftInput = binding(input.left, 'left'); const rightInput = binding(input.right, 'right');
  let left; let right;
  try {
    [left, right] = await Promise.all([
      loadVerifierProfileBundle(leftInput.bundleDirectory, leftInput.expectedProfile),
      loadVerifierProfileBundle(rightInput.bundleDirectory, rightInput.expectedProfile),
    ]);
  } catch (error) {
    fail(`authenticated bundle load failed: ${error.message}`);
  }
  requireDistinct(left.root, right.root, 'bundle directories');
  requireDistinct(left.profileId, right.profileId, 'profile identifiers');
  requireDistinct(left.instanceId, right.instanceId, 'instance identifiers');
  requireEqual(left.manifest.setup.mode, right.manifest.setup.mode, 'setup modes');
  if (!SETUP_MODES.has(left.manifest.setup.mode)) fail('replacement drill setup mode is unsupported');

  const [leftPf7, rightPf7] = await Promise.all([pf7Authority(left), pf7Authority(right)]);
  const leftGenesis = assertGenesis(left, 'left'); const rightGenesis = assertGenesis(right, 'right');
  requireDistinct(canonicalJson(leftGenesis.categoryInputOutpoint), canonicalJson(rightGenesis.categoryInputOutpoint), 'category input outpoints');
  requireDistinct(leftGenesis.stateNftCategory, rightGenesis.stateNftCategory, 'state NFT categories');
  requireDistinct(leftPf7.artifact.sha256, rightPf7.artifact.sha256, 'BCH verifier-set artifacts');
  requireDistinct(leftPf7.authority.sha256, rightPf7.authority.sha256, 'PF7 source-set hashes');
  requireDistinct(
    leftPf7.authority.settlementKernel.artifact.artifacts.stateHelper.sha256,
    rightPf7.authority.settlementKernel.artifact.artifacts.stateHelper.sha256,
    'derived state-helper hashes',
  );

  let leftSdk; let rightSdk;
  try {
    [leftSdk, rightSdk] = await Promise.all([
      createDesktopWalletSdk({ bundleDirectory: leftInput.bundleDirectory, expectedProfile: expectedFor(left) }),
      createDesktopWalletSdk({ bundleDirectory: rightInput.bundleDirectory, expectedProfile: expectedFor(right) }),
    ]);
  } catch (error) {
    fail(`SDK profile loading failed: ${error.message}`);
  }
  const leftSurface = sdkSurface(leftSdk, 'left'); const rightSurface = sdkSurface(rightSdk, 'right');
  requireEqual(canonicalJson(leftSurface), canonicalJson(rightSurface), 'SDK surface');
  try {
    await createDesktopWalletSdk({ bundleDirectory: leftInput.bundleDirectory, expectedProfile: expectedFor(right) });
    fail('SDK accepted a replacement profile for an existing bundle');
  } catch (error) {
    if (error instanceof ProfileReplacementDrillError) throw error;
    if (!(error instanceof WalletSdkError) || error.code !== 'PROFILE_AUTHENTICATION_FAILED') {
      fail(`SDK hot-swap rejection failed: ${error.message}`);
    }
  }

  return Object.freeze({
    schema: 'shield.cash/profile-replacement-drill/v1',
    qualification: 'offline structural replacement drill only; no proof, PF7 verifier VM, ceremony-security, relay, deployment, or release claim',
    setupMode: left.manifest.setup.mode,
    sdk: leftSurface,
    replacements: Object.freeze({
      left: Object.freeze({
        profileId: left.profileId, instanceId: left.instanceId,
        stateNftCategory: leftGenesis.stateNftCategory,
        bchVerifierSetSha256: leftPf7.artifact.sha256,
        pf7SourceSetSha256: leftPf7.authority.sha256,
        stateHelperSha256: leftPf7.authority.settlementKernel.artifact.artifacts.stateHelper.sha256,
      }),
      right: Object.freeze({
        profileId: right.profileId, instanceId: right.instanceId,
        stateNftCategory: rightGenesis.stateNftCategory,
        bchVerifierSetSha256: rightPf7.artifact.sha256,
        pf7SourceSetSha256: rightPf7.authority.sha256,
        stateHelperSha256: rightPf7.authority.settlementKernel.artifact.artifacts.stateHelper.sha256,
      }),
    }),
  });
}
