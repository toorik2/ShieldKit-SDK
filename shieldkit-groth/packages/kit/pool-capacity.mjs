/**
 * Pool capacity / live-note anonymity parameters.
 *
 * maximumLiveNotes = reserveCapSatoshis / DENOMINATION_SATS
 * Fixed denomination: 0.1 BCH per note.
 *
 * Default MAX_NOTES = 16 → 1.6 BCH reserve cap.
 * That is the product default for a real live-note set (not the old 1-note lab pin).
 */

export const DENOMINATION_SATS = 10_000_000n; // 0.1 BCH
export const NOTE_TREE_DEPTH = 32; // structural max 2^32 historical leaves

/** Product default: meaningful live set without absurd Chipnet funding. */
export const DEFAULT_MAX_NOTES = 16;

/** Soft ceiling for create-pool CLI (still ≤ BCH supply / denom). */
export const CREATE_POOL_MAX_NOTES_SOFT = 1024;

/**
 * @param {number|string|bigint} maxNotes
 * @returns {{
 *   maxNotes: number,
 *   denominationSatoshis: string,
 *   reserveCapSatoshis: string,
 *   maxLiveNotes: number,
 *   reserveCapBch: string,
 * }}
 */
export function resolvePoolCapacity(maxNotes = DEFAULT_MAX_NOTES) {
  const n = typeof maxNotes === 'bigint' ? maxNotes : BigInt(maxNotes);
  if (n < 1n) throw new Error('maxNotes must be ≥ 1');
  if (n > CREATE_POOL_MAX_NOTES_SOFT) {
    throw new Error(`maxNotes ${n} exceeds soft CLI ceiling ${CREATE_POOL_MAX_NOTES_SOFT}`);
  }
  const reserve = n * DENOMINATION_SATS;
  const maxNotesNum = Number(n);
  return Object.freeze({
    maxNotes: maxNotesNum,
    denominationSatoshis: DENOMINATION_SATS.toString(),
    reserveCapSatoshis: reserve.toString(),
    maxLiveNotes: maxNotesNum,
    reserveCapBch: (Number(reserve) / 1e8).toFixed(1),
  });
}

/**
 * @param {string|bigint} reserveCapSatoshis
 */
export function capacityFromReserveCap(reserveCapSatoshis) {
  const cap = BigInt(reserveCapSatoshis);
  if (cap < DENOMINATION_SATS || cap % DENOMINATION_SATS !== 0n) {
    throw new Error(`reserveCap ${cap} must be a positive multiple of denomination ${DENOMINATION_SATS}`);
  }
  return resolvePoolCapacity(cap / DENOMINATION_SATS);
}

export function capacitySummary(cap) {
  return {
    maxLiveNotes: cap.maxLiveNotes,
    denominationBch: 0.1,
    reserveCapBch: cap.reserveCapBch,
    note: `Up to ${cap.maxLiveNotes} simultaneous 0.1 BCH notes; live anonymity set ≤ liveNoteCount ≤ ${cap.maxLiveNotes}`,
  };
}
