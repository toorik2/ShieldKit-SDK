#!/usr/bin/env node

import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  buildV2DevelopmentProfilePackage,
  V2DevelopmentProfileError,
} from '../packages/profile/v2/development-profile.mjs';

const OPTIONS = Object.freeze({
  '--build-attestation': 'circuitBuildAttestationPath',
  '--circuit-symbols': 'circuitSymbolPath',
  '--initial-proving-key': 'initialProvingKeyPath',
  '--ptau': 'ptauPath',
  '--proving-key': 'provingKeyPath',
  '--r1cs': 'r1csPath',
  '--setup-attestation': 'developmentSetupAttestationPath',
  '--verification-key': 'verificationKeyPath',
  '--wasm': 'witnessWasmPath',
  '--output': 'outputDirectory',
});

export function parseV2DevelopmentProfileArguments(
  argv,
  cwd = process.cwd(),
) {
  if (!Array.isArray(argv)) {
    throw new V2DevelopmentProfileError(
      'PROFILE_ARGUMENT_INVALID',
      'CLI arguments must be an array',
    );
  }
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    const name = OPTIONS[option];
    if (name === undefined) {
      throw new V2DevelopmentProfileError(
        'PROFILE_ARGUMENT_INVALID',
        `unknown or positional CLI argument: ${String(option)}`,
      );
    }
    if (Object.hasOwn(parsed, name)) {
      throw new V2DevelopmentProfileError(
        'PROFILE_ARGUMENT_INVALID',
        `duplicate CLI option: ${option}`,
      );
    }
    const value = argv[index + 1];
    if (
      typeof value !== 'string'
      || value.length === 0
      || value.startsWith('--')
    ) {
      throw new V2DevelopmentProfileError(
        'PROFILE_ARGUMENT_INVALID',
        `missing path for ${option}`,
      );
    }
    parsed[name] = path.resolve(cwd, value);
  }
  for (const [option, name] of Object.entries(OPTIONS)) {
    if (!Object.hasOwn(parsed, name)) {
      throw new V2DevelopmentProfileError(
        'PROFILE_ARGUMENT_INVALID',
        `missing required CLI option: ${option}`,
      );
    }
  }
  return Object.freeze(parsed);
}

export async function runV2DevelopmentProfile(argv, {
  cwd = process.cwd(),
  repositoryRoot = path.resolve(import.meta.dirname, '../../..'),
} = {}) {
  const configuration = parseV2DevelopmentProfileArguments(argv, cwd);
  return buildV2DevelopmentProfilePackage({
    repositoryRoot,
    ...configuration,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = await runV2DevelopmentProfile(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify({
      schema: 'shieldkit-v2-direct-development-profile-command-result-v1',
      profileId: result.profileId,
      profileCorePath: result.profileCorePath,
      outputDirectory: result.outputDirectory,
      emitted: result.emitted,
    }, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  }
}
