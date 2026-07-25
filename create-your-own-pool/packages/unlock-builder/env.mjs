/**
 * Frozen live unlock-build environment.
 * Authority: live-battery pf7Build (densFuel + length stabilize pin).
 * Do not merge lab/verifier-generator env — missing C7_DENSFUEL_DROP drifts locks.
 */

export const PIN_LENS = Object.freeze([8177, 6654, 7066, 7066, 8393, 7600, 9350]);

export const ROLE_NAMES = Object.freeze([
  'exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal',
]);

/** Static C7 flags shared by every live unlock build (no file paths). */
export const LIVE_UNLOCK_FLAGS = Object.freeze({
  KWIN: '13',
  STRIPED_FRAGS: '5',
  SW: '32',
  CDNW: '1',
  CDWIDTH: '34',
  UNW: '16',
  WDWIDTH: '32',
  WIDE_POS: '',
  FIN_PAD: '',
  C7_MAXTRY: '2',
  NITS: '1',
  RESCHEDULE: 'on',
  SZ_ALLAFF: '1',
  L17SEL: '1',
  SEAMNARROW: '1',
  KSPEC: '1',
  SIBLING_READ: '1',
  FIXED_WDAT: '1',
  DYN_PACK: '1',
  DERIVE_MODE: '1',
  DP: '1',
  STRIPED: '1',
  STRIPE_BOUNDARY: '1',
  DIRECT_FINALIZE_STATE: '1',
  STRICT_DEPLOYMENT: '1',
  PUBLIC_BENCH_CONTEXT: '1',
  DRIVER_PACK_DERIVED: '1',
  DRIVER_WINDOW_DERIVED: '1',
  C7_PROJECTED_BQ_7: '1',
  C7_FIXED_G2_TABLE: '1',
  C7_FIXED_G2_COMPACT: '1',
  C7_FIXED_G2_NORMALIZED_ADDS: '1',
  C7_VK_DIGEST: '1',
  C7_WSEL_U8: '1',
  C7_COMPOSED_P2SH: '1',
  C7_COMPOSED_DIRECT_TERMINAL: '1',
  C7_PAIRFOLD_TOPOLOGY: '7',
  C7_SCALAR_ENDPOINT: '1',
  C7_DENSFUEL_DROP: '1',
  C7_ZBITS_GB3: './normalized-gb3.mjs',
  C7_SZ_MODULE: './mixed-sz.mjs',
  C7_FIXED_G2_UNLOCK_TABLE: '1',
  C7_FIXED_G2_WITNESS_TABLE_BYTES: '0,1536,2460,2427,2304',
  C7_SELF_CARRIED_TERMINAL: '1',
  TERMINAL_FUSION9: '1',
  TERMINAL_REUSE_ZPOWERS: '1',
  TERMINAL_CANON_ZPROLOGUE: '1',
  TERMINAL_FULL_OPT: '1',
  // densFuel-DROP length stabilize (build.ts defaults; explicit for pin docs)
  C7_GENESIS_UNLOCK_TARGET: '7600',
  C7_TERMINAL_UNLOCK_TARGET: '9350',
});

/**
 * Build process.env for one unlock compile.
 * @param {{
 *   unlockRoot: string,
 *   leanRoot: string,
 *   adapterPath: string,
 *   adapterSha256: string,
 *   packetPath: string,
 *   packetSha256: string,
 *   buildDir: string,
 *   genDir: string,
 *   tmpDir: string,
 *   pathPrefix?: string,
 *   nodePath?: string,
 *   home?: string,
 * }} p
 */
export function buildLiveUnlockEnv(p) {
  const cashcRoot = `${p.unlockRoot}/vendor/cashc-resched/packages/cashc`;
  return {
    ...LIVE_UNLOCK_FLAGS,
    PATH: p.pathPrefix
      ? `${p.pathPrefix}:${process.env.PATH || '/usr/bin:/bin'}`
      : (process.env.PATH || '/usr/bin:/bin'),
    HOME: p.home ?? process.env.HOME ?? '',
    TMPDIR: p.tmpDir,
    ...(p.nodePath ? { NODE_PATH: p.nodePath } : {}),
    CASHC_ROOT: cashcRoot,
    LEANBCH_ROOT: p.leanRoot,
    C7_SHIELD_ADAPTER_FILE: p.adapterPath,
    C7_SHIELD_ADAPTER_SHA256: p.adapterSha256,
    C7_STRUCTURAL_ROLE_COUNT: '3',
    C7_SHIELD_ACTION_PACKET_FILE: p.packetPath,
    C7_SHIELD_ACTION_PACKET_SHA256: p.packetSha256,
    C7_TMP: p.buildDir,
    C7_GEN: p.genDir,
  };
}

export function assertPinLens(lens) {
  if (!Array.isArray(lens) || lens.length !== PIN_LENS.length) {
    throw new Error(`unlock pin lens length ${lens?.length} !== ${PIN_LENS.length}`);
  }
  for (let i = 0; i < PIN_LENS.length; i++) {
    if (lens[i] !== PIN_LENS[i]) {
      throw new Error(`unlock pin mismatch at[${i}]: got ${lens[i]} want ${PIN_LENS[i]} (full=${JSON.stringify(lens)})`);
    }
  }
  return lens;
}
