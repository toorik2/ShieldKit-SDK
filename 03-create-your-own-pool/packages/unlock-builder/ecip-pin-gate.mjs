/**
 * densFuel live pin ECIP try-and-increment budget (C7_MAXTRY=2).
 *
 * The genesis redeem hard-requires `nfail <= 2`. For some public-input pairs the
 * ECIP Fiat–Shamir seed needs nfail≥3 (math still holds). densFuel then fails
 * genesis OP_VERIFY deterministically — re-running unlock build on the same
 * adapter is pure waste (~30s × N).
 *
 * Call this *before* spawning densFuel. On ECIP_NFAIL the caller must change
 * public inputs (fee diversity / witness seed) and re-prove — never re-unlock.
 */
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { UnlockBuilderError } from './errors.mjs';
import { LIVE_UNLOCK_FLAGS } from './env.mjs';

const PKG = path.dirname(fileURLToPath(import.meta.url));
const ECIP_FILE = path.join(PKG, 'vendor/verifier/build/chunked/pairing/gen_vkx_ecip.mjs');

/** Live pin envelope — must match C7_MAXTRY / require(nfail <= MT) in densFuel. */
export const PIN_ECIP_MAX_TRY = Number(LIVE_UNLOCK_FLAGS.C7_MAXTRY);

let _ecip = null;

async function loadEcip() {
  if (_ecip) return _ecip;
  if (!existsSync(ECIP_FILE)) {
    throw new UnlockBuilderError('ECIP_MISSING', `gen_vkx_ecip.mjs not found: ${ECIP_FILE}`);
  }
  // Point class identity must match gen_vkx_ecip's @noble resolution (may be
  // external verifier.cash install via createRequire walk).
  const require = createRequire(ECIP_FILE);
  const noblePath = require.resolve('@noble/curves/bn254.js');
  const [{ bn254 }, ecip] = await Promise.all([
    import(pathToFileURL(noblePath).href),
    import(pathToFileURL(ECIP_FILE).href),
  ]);
  _ecip = { G1: bn254.G1.Point, zkEcipHint: ecip.zkEcipHint, ecipVerify: ecip.ecipVerify };
  return _ecip;
}

/**
 * @param {{
 *   adapterPath?: string,
 *   adapter?: object,
 *   maxTry?: number,
 * }} input
 * @returns {Promise<{ nfail: number, ok: boolean, retry0: boolean, maxTry: number, withinBudget: boolean }>}
 */
export async function measureEcipPinBudget(input = {}) {
  const maxTry = input.maxTry ?? PIN_ECIP_MAX_TRY;
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

  const { G1, zkEcipHint, ecipVerify } = await loadEcip();
  const IC = vk.ic.map((p, i) => {
    if (p?.x == null || p?.y == null) {
      throw new UnlockBuilderError('ECIP_INPUT', `ic[${i}] missing x/y`);
    }
    return G1.fromAffine({ x: BigInt(p.x), y: BigInt(p.y) });
  });
  const scalars = [1n, BigInt(fix.in0), BigInt(fix.in1)];
  const hint = zkEcipHint(IC, scalars);
  const v = ecipVerify(IC, scalars, hint);
  return {
    nfail: v.nfail,
    ok: v.ok,
    retry0: v.retry0,
    maxTry,
    withinBudget: v.nfail <= maxTry,
  };
}

/**
 * Throw ECIP_NFAIL if public inputs exceed the live pin's nfail budget.
 * Cheap relative to densFuel (~1s vs ~30s); deterministic for fixed adapter.
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
        + 're-prove with different public inputs (fee/seed diversity) — do not re-unlock',
      m,
    );
  }
  return m;
}
