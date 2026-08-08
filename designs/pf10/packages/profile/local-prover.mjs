// Shared immutable-profile binding for all required local prover surfaces.
// This loader performs no proving, setup, network, or BCH activity.
import path from 'node:path';
import { loadVerifierProfileBundle } from './load.mjs';

const HASH = /^sha256:[0-9a-f]{64}$/;
const fail = (message) => { throw new LocalProverProfileError(message); };
export class LocalProverProfileError extends Error { constructor(message) { super(message); this.name = 'LocalProverProfileError'; } }
const exactKeys = (value, label, expected) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has unexpected keys`);
};

/** Parse a mandatory three-coordinate profile/instance binding before I/O. */
export function parseLocalProverProfileBinding(value, label = 'profile') {
  exactKeys(value, label, ['bundleDirectory', 'expected']);
  if (typeof value.bundleDirectory !== 'string' || !path.isAbsolute(value.bundleDirectory)) fail(`${label}.bundleDirectory must be absolute`);
  exactKeys(value.expected, `${label}.expected`, ['instanceId', 'network', 'profileId']);
  if (value.expected.network !== 'chipnet' && value.expected.network !== 'mainnet') {
    fail(`${label}.expected.network must be chipnet or mainnet`);
  }
  for (const key of ['profileId', 'instanceId']) if (typeof value.expected[key] !== 'string' || !HASH.test(value.expected[key])) fail(`${label}.expected.${key} must be a lowercase sha256 identifier`);
  return value;
}

/** Resolve Groth16 proving artifacts only from the authenticated bundle. */
export async function loadLocalProverProfileBinding(value, label = 'profile') {
  const binding = parseLocalProverProfileBinding(value, label);
  let bundle;
  try { bundle = await loadVerifierProfileBundle(binding.bundleDirectory, binding.expected); }
  catch (error) { fail(`${label} bundle is invalid: ${error.message}`); }
  const artifact = (kind) => {
    const entry = bundle.manifest.artifacts.find((candidate) => candidate.kind === kind);
    if (!entry) fail(`${label} bundle lacks ${kind}`);
    return Object.freeze({ path: path.resolve(bundle.root, ...entry.path.split('/')), sha256: entry.sha256.slice('sha256:'.length) });
  };
  return Object.freeze({
    identity: Object.freeze({ network: bundle.manifest.network.name, profileId: bundle.profileId, instanceId: bundle.instanceId, setupMode: bundle.manifest.setup.mode }),
    artifacts: Object.freeze({ zkey: artifact('proving-key'), verificationKey: artifact('verification-key'), wasm: artifact('witness-generator') }),
  });
}
