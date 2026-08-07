/** Thin bridge so home/resolve can resolve aliases without circular imports. */
import { loadClosedCatalog, showDesign } from '../registry/designs.mjs';
import { resolveAlias } from '../contracts/identity.mjs';
import { ERROR_CODES, cliFail } from '../contracts/errors.mjs';

export { loadClosedCatalog };

export function resolveAliasSafe(alias) {
  try {
    const catalog = loadClosedCatalog();
    return resolveAlias(alias, catalog);
  } catch (error) {
    if (error?.code === 'UNKNOWN_ALIAS') {
      cliFail(ERROR_CODES.UNKNOWN_ALIAS, error.message);
    }
    throw error;
  }
}

export { showDesign };
