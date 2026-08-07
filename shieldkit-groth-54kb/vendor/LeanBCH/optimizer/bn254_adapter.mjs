// bn254_adapter.mjs — portable integration boundary for the BN254 Miller drivers.
//
// chunkplan.mjs is intentionally domain-agnostic. These drivers are not: they need a
// compatible verifier.cash build to generate, compile, and measure BN254 Miller chunks.
// Keep that external layout in one explicit, validated adapter rather than embedding a
// workstation path in every driver.
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

export const BN254_BUILD_ROOT_ENV = 'LEANBCH_BN254_BUILD_ROOT';
export const GENERATED_LAZY_LIBRARY_IMPORT = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';

const layoutFor = (buildRoot) => Object.freeze({
  buildRoot,
  pairingDir: resolve(buildRoot, 'chunked/pairing'),
  generatorModule: resolve(buildRoot, 'chunked/pairing/gen_miller_residue.mjs'),
  millermathModule: resolve(buildRoot, 'chunked/pairing/_millermath.mjs'),
  libauthModule: resolve(buildRoot, 'node_modules/@bitauth/libauth/build/index.js'),
  lazyLibraryPath: resolve(buildRoot, 'singleton/bn254/lib/lazy/Bn254Lazy.cash'),
  generatedLazyLibraryImport: GENERATED_LAZY_LIBRARY_IMPORT,
});

const missingLayoutFiles = (layout) => [
  ['Miller generator', layout.generatorModule],
  ['Miller compiler helpers', layout.millermathModule],
  ['libauth build', layout.libauthModule],
  ['lazy BN254 library', layout.lazyLibraryPath],
].filter(([, path]) => !existsSync(path));

/**
 * Resolve the external build used by the BN254 Miller adapter.
 *
 * An explicit LEANBCH_BN254_BUILD_ROOT wins. Otherwise we accept the convenient
 * sibling checkout <LeanBCH parent>/verifier.cash/build. The latter is only a
 * discovery default: no driver contains a machine-specific absolute path.
 *
 * With optional=true, absence is a structured skip for regression gates that can
 * still run their pure chunkplan checks without the external crown build.
 */
export function resolveBn254Adapter({ optional = false, env = process.env } = {}) {
  const configuredRoot = env[BN254_BUILD_ROOT_ENV];
  const source = configuredRoot ? BN254_BUILD_ROOT_ENV : 'sibling discovery';
  const buildRoot = configuredRoot
    ? resolve(configuredRoot)
    : resolve(HERE, '..', '..', 'verifier.cash', 'build');
  const layout = layoutFor(buildRoot);
  const missing = missingLayoutFiles(layout);
  if (missing.length === 0) return Object.freeze({ ...layout, source });

  const details = missing.map(([name, path]) => `${name}: ${path}`).join('; ');
  const message = [
    `BN254 Miller adapter unavailable (${source}; build root ${buildRoot}).`,
    `Missing required compatible-build files: ${details}.`,
    `Set ${BN254_BUILD_ROOT_ENV}=/path/to/verifier.cash/build to select a compatible build.`,
  ].join(' ');
  if (optional) return Object.freeze({ skip: message });
  throw new Error(message);
}

/** Load the three external modules only after the build layout has been validated. */
export async function loadBn254Adapter(options = {}) {
  const resolved = resolveBn254Adapter(options);
  if (resolved.skip) return resolved;
  try {
    const [generator, millermath, libauth] = await Promise.all([
      import(pathToFileURL(resolved.generatorModule).href),
      import(pathToFileURL(resolved.millermathModule).href),
      import(pathToFileURL(resolved.libauthModule).href),
    ]);
    return Object.freeze({ ...resolved, generator, millermath, libauth });
  } catch (error) {
    const message = `BN254 Miller adapter import failed from ${resolved.buildRoot}: ${String(error?.message ?? error)}`;
    if (options.optional) return Object.freeze({ skip: message });
    throw new Error(message, { cause: error });
  }
}

/**
 * The generated contract imports its lazy library relative to the pairing source.
 * Drivers emit a temporary source file, so rewrite that one import to the validated
 * library path. Refuse a different generator layout instead of silently compiling
 * a source that resolves a different dependency.
 */
export function rewriteGeneratedLazyImport(source, adapter) {
  if (typeof source !== 'string') throw new TypeError('BN254 generated source must be a string');
  const needle = adapter?.generatedLazyLibraryImport;
  const replacement = adapter?.lazyLibraryPath;
  if (typeof needle !== 'string' || typeof replacement !== 'string')
    throw new TypeError('rewriteGeneratedLazyImport requires a resolved BN254 adapter');
  const occurrences = source.split(needle).length - 1;
  if (occurrences !== 1)
    throw new Error(`BN254 generated source must contain exactly one lazy-library import (${needle}); found ${occurrences}`);
  return source.replace(needle, replacement);
}
