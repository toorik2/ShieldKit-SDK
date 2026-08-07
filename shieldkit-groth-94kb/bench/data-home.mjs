/**
 * Portable product data-home resolution for the public bench.
 *
 * Accepts either:
 *   - outer private root  (…/my-install) containing shieldkit/v2-beta-product/session.json
 *   - product directory   (…/v2-beta-product) with session.json
 *
 * No author/machine-specific default paths.
 */
import { existsSync as defaultExistsSync } from 'node:fs';
import path from 'node:path';

export class BenchDataHomeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BenchDataHomeError';
    this.code = code;
  }
}

/**
 * Resolve the product session directory (must contain session.json).
 * @param {string|null|undefined} input
 * @param {{ existsSync?: (p: string) => boolean }} [deps]
 * @returns {string|null} absolute product path or null
 */
export function findProductDataHome(input, deps = {}) {
  const exists = typeof deps.existsSync === 'function' ? deps.existsSync : defaultExistsSync;
  if (typeof input !== 'string' || input.trim().length === 0) return null;
  if (!path.isAbsolute(input)) return null;
  const abs = path.resolve(input);

  const candidates = [
    abs,
    // outer packed root → nested product
    path.join(abs, 'shieldkit', 'v2-beta-product'),
    // parent of outer? (rare: user passed …/shieldkit)
    path.basename(abs) === 'shieldkit' ? path.join(abs, 'v2-beta-product') : null,
  ].filter(Boolean);

  // Prefer paths that already look like product dirs first if session exists
  for (const candidate of candidates) {
    if (exists(path.join(candidate, 'session.json'))) {
      return path.resolve(candidate);
    }
  }
  return null;
}

/**
 * Outer data-home for product CLI when session lives under shieldkit/v2-beta-product.
 * CLI private-config parent rules expect the outer install root in that layout.
 */
export function cliDataHomeFromProduct(productHome) {
  if (typeof productHome !== 'string' || productHome.length === 0) {
    throw new BenchDataHomeError('BENCH_DATA_HOME_INVALID', 'product data-home is required');
  }
  const abs = path.resolve(productHome);
  if (abs.endsWith(`${path.sep}shieldkit${path.sep}v2-beta-product`)) {
    return path.dirname(path.dirname(abs));
  }
  if (path.basename(abs) === 'v2-beta-product'
    && path.basename(path.dirname(abs)) === 'shieldkit') {
    return path.dirname(path.dirname(abs));
  }
  return abs;
}

/**
 * Require a usable product data-home. Throws BenchDataHomeError with a clear code.
 * @param {string|null|undefined} input  --data-home or env value
 * @param {{ existsSync?: (p: string) => boolean, env?: NodeJS.ProcessEnv }} [deps]
 */
export function requireProductDataHome(input, deps = {}) {
  const env = deps.env ?? process.env;
  const explicit = (typeof input === 'string' && input.length > 0)
    ? input
    : (typeof env.SHIELDKIT_BENCH_DATA_HOME === 'string' && env.SHIELDKIT_BENCH_DATA_HOME.length > 0
      ? env.SHIELDKIT_BENCH_DATA_HOME
      : (typeof env.SHIELDKIT_DATA_HOME === 'string' && env.SHIELDKIT_DATA_HOME.length > 0
        ? env.SHIELDKIT_DATA_HOME
        : null));

  if (explicit === null) {
    throw new BenchDataHomeError(
      'BENCH_DATA_HOME_REQUIRED',
      'pass --data-home /absolute/path/to/product-or-install-root '
        + '(or set SHIELDKIT_BENCH_DATA_HOME). '
        + 'Must contain session.json at …/v2-beta-product or …/shieldkit/v2-beta-product.',
    );
  }
  if (!path.isAbsolute(explicit)) {
    throw new BenchDataHomeError(
      'BENCH_DATA_HOME_INVALID',
      `--data-home must be an absolute path (got ${JSON.stringify(explicit)})`,
    );
  }

  const product = findProductDataHome(explicit, deps);
  if (!product) {
    throw new BenchDataHomeError(
      'BENCH_DATA_HOME_UNAVAILABLE',
      `no session.json under ${path.resolve(explicit)} `
        + '(expected …/v2-beta-product/session.json or …/shieldkit/v2-beta-product/session.json). '
        + 'Create and fund a Chipnet product data home first (see docs/product/start.md).',
    );
  }
  return product;
}

/** Env-only resolution for internal helpers (no hardcoded machine paths). */
export function resolveBenchDataHomeFromEnv(env = process.env) {
  if (typeof env.SHIELDKIT_BENCH_DATA_HOME === 'string' && env.SHIELDKIT_BENCH_DATA_HOME.length > 0) {
    return path.resolve(env.SHIELDKIT_BENCH_DATA_HOME);
  }
  if (typeof env.SHIELDKIT_DATA_HOME === 'string' && env.SHIELDKIT_DATA_HOME.length > 0) {
    return path.resolve(env.SHIELDKIT_DATA_HOME);
  }
  return null;
}
