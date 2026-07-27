/**
 * Single init pipeline: setup(mode) → build profile → load.
 * Bridge is internal (not a user step). New setup ⇒ new profile + genesis only.
 */
import path from 'node:path';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import {
  initializeDevelopmentGroth16,
  SNARKJS_VERSION,
  getPinnedSnarkjsInfo,
} from './setup/development.mjs';
import {
  initializeCeremonyGroth16,
  assertCeremonyMetadata,
} from './setup/ceremony.mjs';
import { bridgeLocalSetupToProfile } from './bridge.mjs';
import { buildVerifierProfileBundle } from './build.mjs';
import { loadVerifierProfileBundle } from './load.mjs';

export class ProfileInitError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProfileInitError';
  }
}
const fail = (message) => {
  throw new ProfileInitError(message);
};

const digest = (buf) => `sha256:${createHash('sha256').update(buf).digest('hex')}`;

/**
 * @param {object} input
 * @param {'development-only'|'local-contribution-simulation'} input.mode
 * @param {object} input.setup - args for development or ceremony runner (destination, r1cs, ptau, …)
 * @param {object} [input.bundle] - if set, builds a loadable profile:
 *   { destination, profile, toolchain, network, genesis, artifacts, expected? }
 *   For development: proving-key/verification-key artifacts may omit source (filled from setup).
 *   For ceremony: same; transcript filled from setup outputs.
 * @param {boolean} [input.load=true] - after build, load via loadVerifierProfileBundle
 */
export async function init(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    fail('init input must be an object');
  }
  const mode = input.mode;
  if (mode !== 'development-only' && mode !== 'local-contribution-simulation') {
    fail('mode must be development-only or local-contribution-simulation');
  }
  if (!input.setup || typeof input.setup !== 'object') fail('setup is required');

  let setupResult;
  if (mode === 'development-only') {
    setupResult = await initializeDevelopmentGroth16(input.setup);
    if (setupResult.metadata.mode !== 'development-only') fail('mode laundering refused');
  } else {
    setupResult = await initializeCeremonyGroth16(input.setup);
    assertCeremonyMetadata(setupResult.metadata);
  }

  const out = {
    mode,
    setupDirectory: setupResult.directory,
    setupMetadata: setupResult.metadata,
  };

  if (!input.bundle) {
    return Object.freeze(out);
  }

  const bundle = input.bundle;
  if (!bundle.destination) fail('bundle.destination is required');
  if (mode === 'development-only') {
    const setupMetadataPath = path.join(setupResult.directory, 'setup-metadata.json');
    const setupMetaBytes = await readFile(setupMetadataPath);
    const setupMetadataSha256 = digest(setupMetaBytes);
    // proving-key / verification-key must be descriptors only (id, kind, path).
    // bridgeLocalSetupToProfile injects sources from the local setup directory.
    // Pre-filling source here breaks bridge exactKeys and is ignored/wrong.
    const artifacts = (bundle.artifacts || []).map((a) => {
      if (a.kind === 'proving-key' || a.kind === 'verification-key') {
        const { source: _drop, expectedSha256: _drop2, ...rest } = a;
        return rest;
      }
      return a;
    });
    const built = await bridgeLocalSetupToProfile({
      destination: bundle.destination,
      setupMetadata: {
        sourcePath: setupMetadataPath,
        expectedSha256: setupMetadataSha256,
      },
      profile: bundle.profile,
      toolchain: bundle.toolchain,
      network: bundle.network,
      artifacts,
      genesis: bundle.genesis,
      ...(bundle.expected ? { expected: bundle.expected } : {}),
    });
    out.bundleDirectory = built.directory;
    out.profileId = built.profileId;
    out.instanceId = built.instanceId;
    out.manifest = built.manifest;
  } else {
    // Ceremony: package setup object from metadata + transcript artifact
    const meta = setupResult.metadata;
    const setup = structuredClone(meta.setup);
    // builder derives contributionChainSha256 — strip if present on phase2
    if (setup.material?.phase2?.contributionChainSha256) {
      delete setup.material.phase2.contributionChainSha256;
    }
    const artifacts = (bundle.artifacts || []).map((a) => {
      if (a.kind === 'proving-key' && !a.source) {
        return {
          ...a,
          path: a.path || 'artifacts/final.zkey',
          source: { sourcePath: path.join(setupResult.directory, 'final.zkey') },
        };
      }
      if (a.kind === 'verification-key' && !a.source) {
        return {
          ...a,
          path: a.path || 'artifacts/verification_key.json',
          source: { sourcePath: path.join(setupResult.directory, 'verification_key.json') },
        };
      }
      if (a.kind === 'ceremony-transcript' && !a.source) {
        return {
          ...a,
          path: a.path || 'artifacts/ceremony-transcript.json',
          source: { sourcePath: path.join(setupResult.directory, 'ceremony-transcript.json') },
        };
      }
      return a;
    });
    // ensure transcript artifact exists
    if (!artifacts.some((a) => a.kind === 'ceremony-transcript')) {
      artifacts.push({
        id: 'ceremony-transcript',
        kind: 'ceremony-transcript',
        path: 'artifacts/ceremony-transcript.json',
        source: { sourcePath: path.join(setupResult.directory, 'ceremony-transcript.json') },
      });
    }
    // bind transcript path in setup to artifact path
    const transcriptArt = artifacts.find((a) => a.kind === 'ceremony-transcript');
    setup.transcript = {
      ...setup.transcript,
      artifactPath: transcriptArt.path,
      // sha256/verifier set by builder from artifact + input verifier
      status: 'complete',
      // builder expects transcript: { artifactPath, verifier } in input then completes
    };
    // profile-builder ceremony input shape for setup:
    // { mode, provenance, material, transcript: { artifactPath, verifier }, contributions }
    const setupInput = {
      mode: 'local-contribution-simulation',
      provenance: setup.provenance,
      material: {
        phase1: setup.material.phase1,
        phase2: {
          initializationCommand: setup.material.phase2.initializationCommand,
          finalZkeySha256: setup.material.phase2.finalZkeySha256,
          finalZkeyVerification: setup.material.phase2.finalZkeyVerification,
        },
      },
      transcript: {
        artifactPath: transcriptArt.path,
        verifier: setup.transcript.verifier,
      },
      contributions: setup.contributions,
    };
    artifacts.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const built = await buildVerifierProfileBundle({
      destination: bundle.destination,
      profile: bundle.profile,
      setup: setupInput,
      toolchain: bundle.toolchain,
      network: bundle.network,
      artifacts,
      genesis: bundle.genesis,
      ...(bundle.expected ? { expected: bundle.expected } : {}),
    });
    out.bundleDirectory = built.directory;
    out.profileId = built.profileId;
    out.instanceId = built.instanceId;
    out.manifest = built.manifest;
  }

  if (input.load !== false && out.bundleDirectory) {
    out.loaded = await loadVerifierProfileBundle(out.bundleDirectory, {
      network: bundle.network?.name,
      profileId: out.profileId,
      instanceId: out.instanceId,
    });
  }

  return Object.freeze(out);
}

export { SNARKJS_VERSION, getPinnedSnarkjsInfo };
