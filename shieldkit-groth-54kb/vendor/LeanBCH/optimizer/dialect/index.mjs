// dialect/index.mjs — the dialect registry. Maps a --dialect name to an adapter.
// Adding a bytecode shape = register a new adapter here; nothing else in the tool changes.
import { cashcStandard } from './cashc-standard.mjs';
import { covenantWrapped, looksCovenant } from './covenant-wrapped.mjs';

export const DIALECTS = {
  'cashc-standard': cashcStandard,
  'covenant-wrapped': covenantWrapped,   // analyze-only (deployed covenant chunks)
};

/** Auto-detect the dialect from bytecode: a covenant self-check prologue ⇒ covenant-wrapped
 *  (analyze-only); otherwise the cashc-standard framing. */
export function autoDetect(bytes) {
  return looksCovenant(bytes) ? covenantWrapped : cashcStandard;
}

/** Resolve a dialect by name, or 'auto' (needs `bytes` to sniff). */
export function resolveDialect(name = 'auto', bytes = null) {
  if (name === 'auto') return bytes ? autoDetect(bytes) : cashcStandard;
  const d = DIALECTS[name];
  if (!d) throw new Error(`unknown dialect '${name}' (known: ${Object.keys(DIALECTS).join(', ')})`);
  return d;
}
