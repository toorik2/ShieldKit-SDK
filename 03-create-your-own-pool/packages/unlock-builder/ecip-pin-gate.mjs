/**
 * densFuel live pin ECIP try-and-increment budget (C7_MAXTRY=2).
 *
 * The genesis redeem hard-requires `nfail <= 2`. For some public-input pairs the
 * ECIP Fiat–Shamir seed needs nfail≥3 (math still holds). densFuel then fails
 * genesis OP_VERIFY deterministically — re-running unlock build on the same
 * adapter is pure waste (~30s × N).
 *
 * Call this *before* spawning densFuel. On ECIP_NFAIL the caller must change
 * public inputs (pin-compatible transactionContextHash binding) and prove once —
 * never re-unlock the same adapter.
 */
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { UnlockBuilderError } from './errors.mjs';
import { LIVE_UNLOCK_FLAGS } from './env.mjs';

const PKG = path.dirname(fileURLToPath(import.meta.url));
const ECIP_FILE = path.join(PKG, 'vendor/verifier/build/chunked/pairing/gen_vkx_ecip.mjs');

/** Live pin envelope — must match C7_MAXTRY / require(nfail <= MT) in densFuel. */
export const PIN_ECIP_MAX_TRY = Number(LIVE_UNLOCK_FLAGS.C7_MAXTRY);

let _measure = null;

async function loadMeasure() {
  if (_measure) return _measure;
  if (!existsSync(ECIP_FILE)) {
    throw new UnlockBuilderError('ECIP_MISSING', `gen_vkx_ecip.mjs not found: ${ECIP_FILE}`);
  }
  // Import measure from the ECIP module itself so G1 identity matches zkEcipHint.
  const ecip = await import(pathToFileURL(ECIP_FILE).href);
  if (typeof ecip.measureEcipNfailFromAffine !== 'function') {
    throw new UnlockBuilderError(
      'ECIP_MISSING',
      'gen_vkx_ecip.mjs missing measureEcipNfailFromAffine export',
    );
  }
  _measure = ecip.measureEcipNfailFromAffine;
  return _measure;
}

/**
 * @param {{
 *   adapterPath?: string,
 *   adapter?: object,
 *   maxTry?: number,
 *   in0?: string|bigint,
 *   in1?: string|bigint,
 *   ic?: { x: string|bigint, y: string|bigint }[],
 * }} input
 * @returns {Promise<{ nfail: number, ok: boolean, retry0: boolean, maxTry: number, withinBudget: boolean }>}
 */
export async function measureEcipPinBudget(input = {}) {
  const maxTry = input.maxTry ?? PIN_ECIP_MAX_TRY;
  let ic = input.ic;
  let in0 = input.in0;
  let in1 = input.in1;

  if (ic == null || in0 == null || in1 == null) {
    const adapter = input.adapter
      ?? JSON.parse(readFileSync(input.adapterPath, 'utf8'));
    const fix = adapter?.verifierCashFixture;
    const vk = adapter?.verifierCashVk;
    if (!fix || fix.in0 == null || fix.in1 == null) {
      throw new UnlockBuilderError('ECIP_INPUT', 'adapter.verifierCashFixture.in0/in1 required');
    }
    if (!Array.isArray(vk?.ic) || vk.ic.length !== 3) {
      throw new UnlockBuilderError('ECIP_INPUT', 'adapter.verifierCashVk.ic must be length-3');
    }
    ic = vk.ic;
    in0 = fix.in0;
    in1 = fix.in1;
  }

  if (!Array.isArray(ic) || ic.length !== 3) {
    throw new UnlockBuilderError('ECIP_INPUT', 'ic must be length-3 affine points');
  }

  const measure = await loadMeasure();
  try {
    const v = measure(ic, [1n, BigInt(in0), BigInt(in1)]);
    return {
      nfail: v.nfail,
      ok: v.ok,
      retry0: v.retry0,
      maxTry,
      withinBudget: v.nfail <= maxTry,
    };
  } catch (e) {
    // gen_vkx_ecip throws when try-and-increment exceeds MAXTRY=8 — treat as
    // far outside the live pin budget (nfail > 2), not as a tool crash.
    if (/MAXTRY exceeded/i.test(String(e?.message || e))) {
      return {
        nfail: 9,
        ok: true,
        retry0: false,
        maxTry,
        withinBudget: false,
      };
    }
    throw e;
  }
}

/**
 * Throw ECIP_NFAIL if public inputs exceed the live pin's nfail budget.
 * Cheap relative to densFuel (~ms–1s vs ~30s); deterministic for fixed limbs+VK.
 */
export async function assertEcipWithinPinBudget(input = {}) {
  const m = await measureEcipPinBudget(input);
  if (!m.ok) {
    throw new UnlockBuilderError(
      'ECIP_BROKEN',
      `ecipVerify offline identity failed (LHS≠RHS) nfail=${m.nfail}`,
      m,
    );
  }
  if (!m.withinBudget) {
    throw new UnlockBuilderError(
      'ECIP_NFAIL',
      `public inputs need ECIP nfail=${m.nfail} > pin maxTry=${m.maxTry}; `
        + 'bind pin-compatible transactionContextHash before prove — do not re-unlock',
      m,
    );
  }
  return m;
}
