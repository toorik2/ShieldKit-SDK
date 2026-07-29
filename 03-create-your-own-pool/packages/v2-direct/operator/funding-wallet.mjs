/**
 * Blank-machine transparent funding wallet loader for V2 Direct CLI.
 *
 * Never hard-codes agent/codex wallet paths. Resolution order:
 *   1. explicit path argument
 *   2. V2_FUNDING_WALLET_JSON env
 *   3. <home>/funding-wallet.json
 *
 * Expected JSON (mode 0600 recommended):
 * {
 *   "privateKeyHex": "64 hex",
 *   "publicKeyHex": "compressed pubkey hex",
 *   "lockingBytecodeHex": "P2PKH script hex",
 *   "address": "bchtest:… or bitcoincash:…",
 *   "utxos": [{ "txid", "vout", "valueSats" | "value" }]  // optional
 * }
 */
import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

export class FundingWalletError extends Error {
  constructor(message, code = 'FUNDING_WALLET') {
    super(message);
    this.name = 'FundingWalletError';
    this.code = code;
  }
}

/**
 * @param {{ home?: string, path?: string }} opts
 */
export function resolveFundingWalletPath({ home, path: explicit } = {}) {
  if (explicit) return path.resolve(explicit);
  if (process.env.V2_FUNDING_WALLET_JSON) {
    return path.resolve(process.env.V2_FUNDING_WALLET_JSON);
  }
  if (home) {
    const candidate = path.join(home, 'funding-wallet.json');
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

/**
 * @returns {{
 *   privateKey: Buffer,
 *   publicKey: Buffer,
 *   lockingBytecode: Buffer,
 *   address: string|null,
 *   utxos: { txid: string, vout: number, valueSats: bigint }[],
 *   path: string,
 *   mode: number|null,
 * }}
 */
export function loadFundingWallet({ home, path: explicit } = {}) {
  const walletPath = resolveFundingWalletPath({ home, path: explicit });
  if (!walletPath) {
    throw new FundingWalletError(
      'No funding wallet. Provide --funding-wallet <json>, set V2_FUNDING_WALLET_JSON, '
        + 'or place funding-wallet.json under --home (see Protocol-design-v2 docs).',
      'FUNDING_WALLET_MISSING',
    );
  }
  if (!existsSync(walletPath)) {
    throw new FundingWalletError(`funding wallet not found: ${walletPath}`, 'FUNDING_WALLET_MISSING');
  }
  let mode = null;
  try {
    mode = statSync(walletPath).mode & 0o777;
  } catch {
    mode = null;
  }
  if (mode !== null && mode !== 0o600) {
    // Soft warn via error property — CLI may print; refuse only if world-readable
    if (mode & 0o044) {
      throw new FundingWalletError(
        `funding wallet ${walletPath} mode ${mode.toString(8)} is world/group-readable; chmod 600`,
        'FUNDING_WALLET_INSECURE',
      );
    }
  }
  let raw;
  try {
    raw = JSON.parse(readFileSync(walletPath, 'utf8'));
  } catch (e) {
    throw new FundingWalletError(`invalid funding wallet JSON: ${e.message}`, 'FUNDING_WALLET_INVALID');
  }
  for (const k of ['privateKeyHex', 'publicKeyHex', 'lockingBytecodeHex']) {
    if (typeof raw[k] !== 'string' || !/^[0-9a-fA-F]+$/.test(raw[k])) {
      throw new FundingWalletError(`funding wallet missing/invalid ${k}`, 'FUNDING_WALLET_INVALID');
    }
  }
  const utxos = [];
  if (Array.isArray(raw.utxos)) {
    for (const u of raw.utxos) {
      const txid = String(u.txid || '').toLowerCase();
      const vout = Number(u.vout);
      const valueSats = BigInt(u.valueSats ?? u.value ?? 0);
      if (!/^[0-9a-f]{64}$/.test(txid) || !Number.isInteger(vout) || vout < 0 || valueSats <= 0n) {
        throw new FundingWalletError('funding wallet utxos entry invalid', 'FUNDING_WALLET_INVALID');
      }
      utxos.push({ txid, vout, valueSats });
    }
  }
  return {
    privateKey: Buffer.from(raw.privateKeyHex, 'hex'),
    publicKey: Buffer.from(raw.publicKeyHex, 'hex'),
    lockingBytecode: Buffer.from(raw.lockingBytecodeHex, 'hex'),
    address: raw.address || null,
    utxos,
    path: walletPath,
    mode,
  };
}

/**
 * Pick a funding UTXO ≥ need from wallet.utxos or optional scanned list.
 * @param {{ utxos: {txid,vout,valueSats}[] }} wallet
 * @param {bigint} need
 */
export function selectFundingUtxoFromList(wallet, need, label = 'funding') {
  const needN = BigInt(need);
  const sorted = [...(wallet.utxos || [])].sort((a, b) => (
    a.valueSats === b.valueSats ? 0 : (a.valueSats > b.valueSats ? -1 : 1)
  ));
  const hit = sorted.find((u) => u.valueSats >= needN);
  if (!hit) {
    throw new FundingWalletError(
      `FUNDING_UTXO_REQUIRED: need ≥ ${needN} sats for ${label}; `
        + `add utxos to funding-wallet.json or pass --category-utxo / --fee-utxo`,
      'FUNDING_UTXO_REQUIRED',
    );
  }
  return hit;
}
