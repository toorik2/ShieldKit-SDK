/**
 * Single toolkit version source: monorepo root package.json.
 * Profile/instance identities are content hashes — never this number.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// this file lives in shieldkit-groth-94kb/ → monorepo root is parent
const monorepoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(path.join(monorepoRoot, 'package.json'), 'utf8'));

/** Toolkit semver (code surface only). */
export const TOOLKIT_VERSION = String(pkg.version);

/** Pre-1.0: minors may break. Not a maturity claim. */
export const TOOLKIT_VERSIONING = Object.freeze({
  version: TOOLKIT_VERSION,
  scheme: 'semver-0.y.z',
  until1_0: '0.y.z — MINOR may include breaking API changes; not production-qualified',
  status: 'ShieldKit-Groth Beta — Unaudited Chipnet-only',
  maturityLabel: 'beta (zero-conf Chipnet; not production-qualified)',
  product: 'ShieldKit-Groth',
  release: 'ShieldKit-Groth Beta',
  note: 'Toolkit version ≠ profileId ≠ instanceId ≠ privacy/mainnet qualification',
});

export function toolkitIdentity() {
  return {
    toolkitVersion: TOOLKIT_VERSION,
    product: TOOLKIT_VERSIONING.product,
    release: TOOLKIT_VERSIONING.release,
    status: TOOLKIT_VERSIONING.status,
    maturityLabel: TOOLKIT_VERSIONING.maturityLabel,
    versioningNote: TOOLKIT_VERSIONING.note,
  };
}
