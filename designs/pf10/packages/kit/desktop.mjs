// Desktop/offline wallet facade. This composition layer accepts no private
// keys, opens no network connections, persists nothing, and broadcasts nothing.
import {
  generateSigningSerializationBch,
  hash256,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';
import { loadVerifierProfileBundle } from '../profile/load.mjs';
import {
  WalletSdkError,
  createBrowserWalletSdk,
  createProfileCoordinates,
  requireLocalProverCapability,
} from './browser.mjs';

const fail = (code, message) => { throw new WalletSdkError(code, message); };
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail('INVALID_OBJECT', `${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail('UNKNOWN_PROPERTY', `${label} has missing or unknown properties`);
};
const canonicalHex = (value, bytes, label) => {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) fail('MALFORMED_BYTES', `${label} must be ${bytes} lowercase hexadecimal bytes`);
  return value;
};
const profileExpectation = (profile) => Object.freeze({ network: profile.network, profileId: profile.profileId, instanceId: profile.instanceId });
// Keep the desktop facade importable in a bare application environment. Each
// heavyweight primitive is loaded only when its explicit offline workflow is
// selected; it remains profile-authenticated and never has a network fallback.
const legacyMoved = (name) => () => {
  const error = new Error(`${name} moved to designs/pf10/research/v1-seven-carrier/; use shieldkit pool * for PF10`);
  error.code = 'LEGACY_V1_PATH_MOVED';
  return Promise.reject(error);
};
const preparationPrimitive = legacyMoved('action/prep');
const settlementPrimitive = legacyMoved('action/settlement');
const witnessPrimitive = legacyMoved('action/assemble');
const genesisPrimitive = legacyMoved('profile/genesis');
const signingRequest = (plan, label) => {
  const serialization = generateSigningSerializationBch({
    inputIndex: 0,
    sourceOutputs: [plan.sourceOutput],
    transaction: plan.unsignedTransaction,
  }, {
    coveredBytecode: plan.sourceOutput.lockingBytecode,
    signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
  });
  const digest = hash256(serialization);
  return Object.freeze({
    schema: 'shield.cash/bch-schnorr-signature-request/v1',
    qualification: 'offline signing request only; caller controls key custody and transport',
    label,
    algorithm: 'bch-schnorr-all-forkid',
    signingSerialization: Uint8Array.from(serialization),
    signingSerializationHex: Buffer.from(serialization).toString('hex'),
    digest: Uint8Array.from(digest),
    digestHex: Buffer.from(digest).toString('hex'),
  });
};

function completePreparationInput(profile, value) {
  exactKeys(value, 'complete preparation request', ['bindingCarrierBaseValueSatoshis', 'bindingLockingBytecode', 'fundingOutpointIndex', 'fundingOutpointTransactionHashWire', 'fundingPublicKey', 'fundingSourceValueSatoshis', 'kind', 'settlementFeeFundingSatoshis']);
  return Object.freeze({
    ...value,
    bundleDirectory: profile.bundleDirectory,
    expectedProfile: profileExpectation(profile),
    minimumFeeRateSatoshisPerByte: '1',
  });
}

/** Load a hash-authenticated immutable profile and expose offline-only methods. */
export async function createDesktopComposition(value) {
  exactKeys(value, 'desktop wallet SDK input', ['bundleDirectory', 'expectedProfile']);
  if (typeof value.bundleDirectory !== 'string' || value.bundleDirectory.length === 0) fail('PROFILE_BUNDLE_REQUIRED', 'bundleDirectory is required');
  const expected = createProfileCoordinates(value.expectedProfile);
  let bundle;
  try { bundle = await loadVerifierProfileBundle(value.bundleDirectory, expected); }
  catch (error) { fail('PROFILE_AUTHENTICATION_FAILED', `profile bundle rejected: ${error.message}`); }
  const profile = Object.freeze({ ...expected, bundleDirectory: value.bundleDirectory, setupMode: bundle.manifest.setup.mode, stateNftCategory: bundle.manifest.genesis.stateNftCategory });
  // The portable facade intentionally accepts only the immutable public
  // profile coordinates, not desktop-only bundle metadata.
  const portable = createBrowserWalletSdk({ profile: expected });
  return Object.freeze({
    schema: 'shield.cash/desktop-wallet-sdk/v2',
    profile,
    qualification: profile.setupMode === 'development-only'
      ? 'development-only local profile; not ceremony or production qualification'
      : 'ceremony profile loaded locally; no release qualification claim',
    deriveRecipientAddress: portable.deriveRecipientAddress,
    constructRecipientOutput: portable.constructRecipientOutput,
    recoverChainOutput: portable.recoverChainOutput,
    recoverAuthenticatedHistory: portable.recoverAuthenticatedHistory,
    serializeHistoryActions: portable.serializeHistoryActions,
    requireLocalProver: requireLocalProverCapability,
    async planCompletePreparation(request) {
      return (await preparationPrimitive()).planCompletePreparationTransaction(completePreparationInput(profile, request));
    },
    async preparationSigningRequest(request) {
      return signingRequest(await (await preparationPrimitive()).planCompletePreparationTransaction(completePreparationInput(profile, request)), 'complete-preparation-input-0');
    },
    async finalizeCompletePreparation(request, signatureHex) {
      canonicalHex(signatureHex, 64, 'signature');
      return (await preparationPrimitive()).finalizeCompletePreparationTransaction(completePreparationInput(profile, request), signatureHex);
    },
    async planWitnessBoundSettlements(value) {
      exactKeys(value, 'witness-bound settlement request', ['localProver', 'settlements', 'withdrawalScriptHash', 'witnessSeed']);
      requireLocalProverCapability(value.localProver);
      canonicalHex(value.withdrawalScriptHash, 32, 'withdrawalScriptHash'); canonicalHex(value.witnessSeed, 32, 'witnessSeed');
      return (await witnessPrimitive()).generateWitnessBoundSettlementPlans({
        settlements: value.settlements,
        witness: {
          bundleDirectory: profile.bundleDirectory,
          expectedProfile: profileExpectation(profile),
          withdrawalScriptHash: value.withdrawalScriptHash,
          witnessSeed: value.witnessSeed,
        },
      });
    },
    serializeCompleteSettlement(value) {
      exactKeys(value, 'complete settlement request', ['actionPacket', 'bindingCarrierBaseValueSatoshis', 'inputs', 'kind', 'outputs', 'sourceOutputs', 'stateCarrierBaseValueSatoshis']);
      return settlementPrimitive().then(({ buildSettlementTransaction }) => buildSettlementTransaction({
        ...value,
        profileId: profile.profileId.slice('sha256:'.length),
        instanceId: profile.instanceId.slice('sha256:'.length),
        minimumFeeRateSatoshisPerByte: '1',
      }));
    },
    async planGenesis(value) {
      exactKeys(value, 'Chipnet genesis request', ['categoryInput']);
      return (await genesisPrimitive()).planChipnetGenesisTransaction({
        ...value, bundleDirectory: profile.bundleDirectory, expectedProfile: profileExpectation(profile),
        bindingCarrierBaseSatoshis: '1000', stateCarrierBaseSatoshis: '1080', minimumFeeRateSatoshisPerByte: '1',
      });
    },
    async finalizeGenesis(value, signatureHex) {
      canonicalHex(signatureHex, 64, 'signature');
      exactKeys(value, 'Chipnet genesis request', ['categoryInput']);
      return (await genesisPrimitive()).finalizeChipnetGenesisTransaction({
        ...value, bundleDirectory: profile.bundleDirectory, expectedProfile: profileExpectation(profile),
        bindingCarrierBaseSatoshis: '1000', stateCarrierBaseSatoshis: '1080', minimumFeeRateSatoshisPerByte: '1',
      }, signatureHex);
    },
  });
}

export { WalletSdkError, createBrowserWalletSdk, createProfileCoordinates, requireLocalProverCapability };
