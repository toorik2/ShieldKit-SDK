// Node-only raw-BCH structural parsing. This module does not implement BCH
// consensus: caller-provided raw blocks are untrusted until a BCHN RPC snapshot
// is checked by fetchBchnRawChainSegment.
import { hash256, readCompactUintMinimal, readTransactionCommon } from '@bitauth/libauth';
import { bytesToHex, hexToBytes, isBytes } from './portable-core.mjs';
import { extractRawSettlementHistory } from './raw-settlement-history.mjs';

const HEADER_BYTES = 80; const MAX_BLOCK_TRANSACTIONS = 1_000_000; const MAX_BCHN_SUFFIX_BLOCKS = 10_000; const U256 = 1n << 256n;
export class RawChainRecoveryError extends Error { constructor(code, message) { super(message); this.name = 'RawChainRecoveryError'; this.code = code; } }
const fail = (code, message) => { throw new RawChainRecoveryError(code, message); };
const exactKeys = (value, label, keys) => { if (value === null || Array.isArray(value) || typeof value !== 'object') fail('INVALID_OBJECT', `${label} must be an object`); const actual = Object.keys(value).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('UNKNOWN_PROPERTY', `${label} has missing or unknown properties`); };
const hex32 = (value, label) => { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('INVALID_IDENTIFIER', `${label} must be 32 lowercase hexadecimal bytes`); return value; };
const decimal = (value, label) => { if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) fail('INVALID_CHAINWORK', `${label} must be canonical decimal`); return BigInt(value); };
const uint = (value, label) => { if (!Number.isSafeInteger(value) || value < 0) fail('INVALID_HEIGHT', `${label} must be a non-negative safe integer`); return value; };
const bytes = (value, label) => { if (!isBytes(value)) fail('INVALID_BYTES', `${label} must be Uint8Array`); return new Uint8Array(value); };
const displayHash = (value) => bytesToHex(new Uint8Array(hash256(value)).reverse());
const uint32le = (value, offset) => value[offset] | (value[offset + 1] << 8) | (value[offset + 2] << 16) | (value[offset + 3] * 0x1000000);
const targetFromBits = (bits) => { const exponent = bits >>> 24; const mantissa = bits & 0x007fffff; if ((bits & 0x00800000) !== 0 || mantissa === 0 || exponent === 0 || exponent > 32) fail('INVALID_TARGET', 'header compact target is invalid'); const target = exponent <= 3 ? BigInt(mantissa) >> (8n * BigInt(3 - exponent)) : BigInt(mantissa) << (8n * BigInt(exponent - 3)); if (target <= 0n || target >= U256) fail('INVALID_TARGET', 'header target is outside uint256'); return target; };
const headerWork = (target) => U256 / (target + 1n);
const header = (rawHeader, maximumTarget) => { const raw = bytes(rawHeader, 'header'); if (raw.length !== HEADER_BYTES) fail('MALFORMED_HEADER', 'block header must be exactly 80 bytes'); const bits = uint32le(raw, 72); const target = targetFromBits(bits); if (target > maximumTarget) fail('TARGET_EXCEEDS_MAXIMUM', 'header target exceeds pinned maximum target'); const id = displayHash(raw); if (BigInt(`0x${id}`) > target) fail('INVALID_PROOF_OF_WORK', 'header hash does not satisfy its target'); return Object.freeze({ raw, id, previousBlockHash: bytesToHex(raw.subarray(4, 36).reverse()), merkleRoot: bytesToHex(raw.subarray(36, 68).reverse()), bits, target, work: headerWork(target) }); };
const readCount = (bin, index, label) => { const result = readCompactUintMinimal({ bin, index }); if (typeof result === 'string' || result.result > BigInt(MAX_BLOCK_TRANSACTIONS)) fail('MALFORMED_BLOCK', `${label} compact count is invalid`); return { count: Number(result.result), index: result.position.index }; };
const merkleRoot = (transactions) => { let level = transactions.map((transaction) => new Uint8Array(hash256(transaction.raw))); if (level.length === 0) fail('MALFORMED_BLOCK', 'block must include at least one transaction'); while (level.length > 1) { if (level.length % 2 === 1) level.push(level.at(-1)); const next = []; for (let index = 0; index < level.length; index += 2) { const pair = new Uint8Array(64); pair.set(level[index]); pair.set(level[index + 1], 32); next.push(new Uint8Array(hash256(pair))); } level = next; } return bytesToHex(level[0].reverse()); };

/**
 * Parse one complete raw-block-shaped byte string and authenticate its
 * transaction merkle root. This is an untrusted structural parser, not BCH
 * consensus validation: it does not establish coinbase, difficulty, UTXO, VM,
 * or canonical-chain validity.
 */
export function parseRawBchBlock(value, { maximumTarget } = {}) {
  if (typeof maximumTarget !== 'string' || !/^[0-9a-f]{64}$/.test(maximumTarget) || maximumTarget === '0'.repeat(64)) fail('INVALID_MAXIMUM_TARGET', 'maximumTarget must be a nonzero 32-byte lowercase hexadecimal target');
  const raw = bytes(value, 'rawBlock'); if (raw.length <= HEADER_BYTES) fail('MALFORMED_BLOCK', 'block is shorter than header plus transaction count'); const parsedHeader = header(raw.subarray(0, HEADER_BYTES), BigInt(`0x${maximumTarget}`)); const count = readCount(raw, HEADER_BYTES, 'transaction'); if (count.count === 0) fail('MALFORMED_BLOCK', 'block must include a coinbase transaction');
  const transactions = []; let index = count.index;
  for (let transactionIndex = 0; transactionIndex < count.count; transactionIndex += 1) { const parsed = readTransactionCommon({ bin: raw, index }); if (typeof parsed === 'string' || parsed.position.index <= index) fail('MALFORMED_TRANSACTION', `transaction ${transactionIndex} cannot be parsed`); const transactionRaw = new Uint8Array(raw.subarray(index, parsed.position.index)); transactions.push(Object.freeze({ id: displayHash(transactionRaw), raw: transactionRaw, transaction: parsed.result })); index = parsed.position.index; }
  if (index !== raw.length) fail('MALFORMED_BLOCK', 'block includes trailing bytes'); if (merkleRoot(transactions) !== parsedHeader.merkleRoot) fail('MERKLE_ROOT_MISMATCH', 'block header merkle root does not match its raw transactions'); return Object.freeze({ schema: 'shield.cash/raw-bch-block/v1', ...parsedHeader, transactions: Object.freeze(transactions) });
}

function checkpoint(value) { exactKeys(value, 'checkpoint', ['blockHash', 'chainwork', 'height', 'maximumTarget']); const maximumTarget = hex32(value.maximumTarget, 'checkpoint.maximumTarget'); return Object.freeze({ blockHash: hex32(value.blockHash, 'checkpoint.blockHash'), height: uint(value.height, 'checkpoint.height'), chainwork: decimal(value.chainwork, 'checkpoint.chainwork'), maximumTarget }); }
function tip(value) { exactKeys(value, 'tip', ['blockHash', 'chainwork', 'height']); return Object.freeze({ blockHash: hex32(value.blockHash, 'tip.blockHash'), height: uint(value.height, 'tip.height'), chainwork: decimal(value.chainwork, 'tip.chainwork') }); }

/**
 * Verify an untrusted contiguous raw-block suffix against caller-pinned
 * checkpoint and tip values. This structural mode is not a G5 recovery path;
 * use fetchBchnRawChainSegment with a self-hosted BCHN node for its bounded
 * canonical-node consistency checks.
 */
export function verifyRawChainSegment(value) {
  exactKeys(value, 'raw chain segment', ['checkpoint', 'rawBlocks', 'tip']); const anchor = checkpoint(value.checkpoint); const expectedTip = tip(value.tip); if (!Array.isArray(value.rawBlocks)) fail('INVALID_BLOCKS', 'rawBlocks must be an array'); const expectedLength = expectedTip.height - anchor.height; if (expectedLength < 0 || value.rawBlocks.length !== expectedLength) fail('TRUNCATED_CHAIN', 'raw block count does not cover exactly checkpoint through tip');
  let parent = anchor.blockHash; let work = anchor.chainwork; const blocks = [];
  for (let index = 0; index < value.rawBlocks.length; index += 1) { const block = parseRawBchBlock(value.rawBlocks[index], { maximumTarget: anchor.maximumTarget }); if (block.previousBlockHash !== parent) fail('HEADER_LINKAGE', `block ${index} does not link to its authenticated parent`); parent = block.id; work += block.work; blocks.push(Object.freeze({ ...block, height: anchor.height + index + 1, chainwork: work.toString(10) })); }
  if (parent !== expectedTip.blockHash || work !== expectedTip.chainwork) fail('TIP_MISMATCH', 'raw header chain does not match the pinned tip hash and chainwork'); return Object.freeze({ schema: 'shield.cash/raw-chain-segment/v1', qualification: 'UNTRUSTED structural parsing only: raw-header linkage, structural PoW, cumulative work, merkle, and transaction boundaries. It is not BCH consensus, canonical-chain authentication, independent implementation, or G5 recovery evidence.', checkpoint: { ...anchor, chainwork: anchor.chainwork.toString(10) }, tip: { ...expectedTip, chainwork: expectedTip.chainwork.toString(10) }, blocks: Object.freeze(blocks) });
}

function settlement(value) { exactKeys(value, 'settlement config', ['genesisRawTransaction', 'genesisTransactionId', 'instanceId', 'profileId', 'stateCarrierBaseSatoshis', 'stateLockSha256', 'stateLockingBytecode', 'stateNftCategory']); const genesisRawTransaction = bytes(value.genesisRawTransaction, 'settlement.genesisRawTransaction'); const genesisTransactionId = hex32(value.genesisTransactionId, 'settlement.genesisTransactionId'); if (displayHash(genesisRawTransaction) !== genesisTransactionId) fail('GENESIS_ID', 'settlement genesis bytes do not match genesisTransactionId'); return Object.freeze({ ...value, genesisRawTransaction, genesisTransactionId }); }
const stateSpend = (transaction) => transaction.inputs.length >= 9 && transaction.inputs[8].outpointIndex === 0 ? bytesToHex(transaction.inputs[8].outpointTransactionHash) : undefined;
const historyInput = (config, rawTransactions) => ({ genesisTransactionId: config.genesisTransactionId, instanceId: config.instanceId, profileId: config.profileId, stateCarrierBaseSatoshis: config.stateCarrierBaseSatoshis, stateLockSha256: config.stateLockSha256, stateLockingBytecode: config.stateLockingBytecode, stateNftCategory: config.stateNftCategory, rawTransactions });

/** Extract only the contiguous, profile-bound state chain from authenticated blocks. */
export function extractProfileBoundSettlements(value) {
  exactKeys(value, 'profile settlement extraction', ['blocks', 'settlement']); const config = settlement(value.settlement); if (!Array.isArray(value.blocks)) fail('INVALID_BLOCKS', 'blocks must be an array'); const rawTransactions = [config.genesisRawTransaction]; const stateIds = new Set([config.genesisTransactionId]); let parent = config.genesisTransactionId;
  for (const block of value.blocks) { if (block === null || !Array.isArray(block.transactions)) fail('INVALID_BLOCKS', 'blocks must come from verifyRawChainSegment'); for (const row of block.transactions) { if (!row || typeof row.id !== 'string' || !isBytes(row.raw) || !row.transaction) fail('INVALID_BLOCKS', 'block transaction is malformed'); if (row.id === config.genesisTransactionId) fail('DUPLICATE_GENESIS', 'genesis transaction must not appear in recovered suffix'); const spend = stateSpend(row.transaction); if (spend === undefined || !stateIds.has(spend)) continue; if (spend !== parent) fail('STATE_FORK', 'a transaction spends an earlier state anchor after its successor exists'); if (row.transaction.inputs.length !== 10) fail('SETTLEMENT_INPUT_COUNT', 'state-anchor spend does not have the fixed ten-input topology'); rawTransactions.push(new Uint8Array(row.raw)); try { extractRawSettlementHistory(historyInput(config, rawTransactions)); } catch (error) { fail(error.code ?? 'INVALID_SETTLEMENT', `profile-bound settlement rejected: ${error.message}`); } parent = row.id; stateIds.add(parent); } }
  const history = rawTransactions.length === 1 ? undefined : extractRawSettlementHistory(historyInput(config, rawTransactions)); return Object.freeze({ schema: 'shield.cash/profile-settlement-chain/v1', qualification: 'authenticated raw-chain structural extraction only; BCH VM/script validity and independent implementation remain separate gates', confirmedTransactionIds: Object.freeze(rawTransactions.map((entry) => displayHash(entry))), settlementTransactionIds: Object.freeze(rawTransactions.slice(1).map((entry) => displayHash(entry))), terminalStateTransactionId: parent, history });
}

function settlementWithRaw(value, segment) { const config = settlement(value); const extracted = extractProfileBoundSettlements({ settlement: config, blocks: segment.blocks }); const rawTransactions = [config.genesisRawTransaction]; const known = new Set([config.genesisTransactionId]); let parent = config.genesisTransactionId; for (const block of segment.blocks) for (const row of block.transactions) { const spend = stateSpend(row.transaction); if (spend !== parent || !known.has(spend) || row.transaction.inputs.length !== 10) continue; rawTransactions.push(new Uint8Array(row.raw)); parent = row.id; known.add(parent); } return Object.freeze({ config, extracted, confirmedRawTransactions: Object.freeze(rawTransactions), terminalStateTransactionId: extracted.terminalStateTransactionId }); }
function pending(value, config, confirmed) { if (value === undefined) return Object.freeze({ status: 'none', transactions: Object.freeze([]) }); if (!Array.isArray(value)) fail('INVALID_PENDING', 'pendingTransactions must be an array'); const ids = new Set(); const candidates = []; for (const entry of value) { const raw = bytes(entry, 'pending transaction'); const parsed = readTransactionCommon({ bin: raw, index: 0 }); if (typeof parsed === 'string' || parsed.position.index !== raw.length) fail('MALFORMED_TRANSACTION', 'pending transaction cannot be parsed'); const id = displayHash(raw); if (ids.has(id)) fail('DUPLICATE_PENDING', 'pending transaction identifier repeats'); ids.add(id); if (stateSpend(parsed.result) === confirmed.terminalStateTransactionId) { if (parsed.result.inputs.length !== 10) fail('SETTLEMENT_INPUT_COUNT', 'pending state spend does not have the fixed ten-input topology'); try { extractRawSettlementHistory(historyInput(config, [...confirmed.confirmedRawTransactions, raw])); } catch (error) { fail(error.code ?? 'INVALID_PENDING_SETTLEMENT', `pending settlement rejected: ${error.message}`); } candidates.push(Object.freeze({ id, raw: new Uint8Array(raw) })); } } const status = candidates.length === 0 ? 'none' : candidates.length === 1 ? 'pending' : 'conflicted'; return Object.freeze({ status, transactions: Object.freeze(candidates) }); }

/**
 * Keep an in-memory journal for untrusted structural segments. Its supplied
 * tips and raw blocks are not a BCH canonicality oracle and it is not a G5
 * recovery path; feed it only data already authenticated by a stronger source.
 */
export function createRawChainRecoveryJournal(config) {
  exactKeys(config, 'raw chain journal config', ['checkpoint', 'settlement']); const frozenCheckpoint = checkpoint(config.checkpoint); const frozenSettlement = settlement(config.settlement); let current;
  return Object.freeze({ reconcile(value) { exactKeys(value, 'raw chain reconciliation', ['pendingTransactions', 'rawBlocks', 'tip']); const segment = verifyRawChainSegment({ checkpoint: { ...frozenCheckpoint, chainwork: frozenCheckpoint.chainwork.toString(10) }, rawBlocks: value.rawBlocks, tip: value.tip }); let common = 0; if (current !== undefined) { while (common < current.segment.blocks.length && common < segment.blocks.length && current.segment.blocks[common].id === segment.blocks[common].id) common += 1; const diverged = common !== current.segment.blocks.length || common !== segment.blocks.length; if (diverged && BigInt(segment.tip.chainwork) <= BigInt(current.segment.tip.chainwork)) fail('PROVIDER_EQUIVOCATION', 'conflicting provider branch does not have strictly greater authenticated work'); } const confirmed = settlementWithRaw(frozenSettlement, segment); const pendingState = pending(value.pendingTransactions, frozenSettlement, confirmed); const rollbackDepth = current === undefined ? 0 : current.segment.blocks.length - common; const appliedBlocks = current === undefined ? segment.blocks.length : segment.blocks.length - common; current = Object.freeze({ segment, confirmed, pending: pendingState }); return Object.freeze({ schema: 'shield.cash/raw-chain-recovery-state/v1', qualification: 'UNTRUSTED structural parsing and profile-bound settlement reconstruction only; no BCH VM validation, canonical-chain authentication, node consensus, independent implementation, or G5 evidence.', checkpoint: segment.checkpoint, tip: segment.tip, rollbackDepth, appliedBlocks, confirmed: confirmed.extracted, pending: pendingState }); }, snapshot() { return current === undefined ? undefined : current; } });
}

const rpcHex = (value, label) => { if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) fail('RPC_MALFORMED', `${label} must be lowercase even-length hexadecimal`); return hexToBytes(value); };
const rpcChainwork = (value, label) => { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('RPC_MALFORMED', `${label} must be a 32-byte lowercase hexadecimal chainwork value`); return BigInt(`0x${value}`); };
const rpcInfo = (value) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail('RPC_MALFORMED', 'BCHN getblockchaininfo result is malformed');
  // BCHN's canonical getblockchaininfo identifier for Chipnet is `chip`.
  if (value.chain !== 'chip') fail('WRONG_NETWORK', 'BCHN provider is not on Chipnet');
  if (value.pruned === true) fail('PRUNED_NODE', 'a pruned BCHN node is not an acceptable chain-recovery provider');
  if (value.pruned !== false || value.initialblockdownload === true) fail('NODE_NOT_READY', 'BCHN provider must report a fully available, non-IBD chain');
  const blocks = uint(value.blocks, 'BCHN blocks'); const headers = uint(value.headers, 'BCHN headers');
  if (blocks !== headers) fail('NODE_NOT_READY', 'BCHN block and header counts disagree');
  return Object.freeze({ blocks, bestBlockHash: hex32(value.bestblockhash, 'BCHN best block hash'), chainwork: rpcChainwork(value.chainwork, 'BCHN chainwork') });
};
const rpcHeader = (value, { expectedHash, expectedHeight, expectedParent, expectedWork }) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail('RPC_MALFORMED', `BCHN verbose header at height ${expectedHeight} is malformed`);
  if (hex32(value.hash, `BCHN verbose header hash at height ${expectedHeight}`) !== expectedHash || uint(value.height, `BCHN verbose header height at ${expectedHeight}`) !== expectedHeight || hex32(value.previousblockhash, `BCHN verbose header parent at ${expectedHeight}`) !== expectedParent || rpcChainwork(value.chainwork, `BCHN verbose header chainwork at ${expectedHeight}`) !== expectedWork || !Number.isSafeInteger(value.confirmations) || value.confirmations < 1) fail('RPC_EQUIVOCATION', `BCHN verbose header disagrees with the canonical snapshot at height ${expectedHeight}`);
};
const rpcCheckpointHeader = (value, anchor) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail('RPC_MALFORMED', 'BCHN verbose checkpoint header is malformed');
  if (hex32(value.hash, 'BCHN verbose checkpoint hash') !== anchor.blockHash || uint(value.height, 'BCHN verbose checkpoint height') !== anchor.height || rpcChainwork(value.chainwork, 'BCHN verbose checkpoint chainwork') !== anchor.chainwork || !Number.isSafeInteger(value.confirmations) || value.confirmations < 1) fail('RPC_CHECKPOINT_MISMATCH', 'BCHN canonical checkpoint disagrees with the authenticated checkpoint');
};
const sameRpcInfo = (left, right) => left.blocks === right.blocks && left.bestBlockHash === right.bestBlockHash && left.chainwork === right.chainwork;
/**
 * Fetch one stable canonical Chipnet suffix from a caller-supplied BCHN JSON-RPC
 * transport. The node selects the tip and every hash by height; callers supply
 * only the already-authenticated checkpoint. `request` receives method and
 * params only, so this adapter neither stores nor logs credentials.
 */
export async function fetchBchnRawChainSegment(value) {
  exactKeys(value, 'BCHN raw chain request', ['checkpoint', 'request']); const anchor = checkpoint(value.checkpoint); const { request } = value;
  if (typeof request !== 'function') fail('INVALID_TRANSPORT', 'request must be a caller-supplied JSON-RPC transport');
  const call = async (method, params, label) => { try { return await request(method, params); } catch { fail('RPC_UNAVAILABLE', `BCHN ${label} request failed`); } };
  const initial = rpcInfo(await call('getblockchaininfo', [], 'getblockchaininfo'));
  if (anchor.height > initial.blocks) fail('NODE_STALE', 'BCHN provider has not reached the authenticated checkpoint height');
  if (initial.blocks - anchor.height > MAX_BCHN_SUFFIX_BLOCKS) fail('SCAN_RANGE_LIMIT', `BCHN suffix exceeds the ${MAX_BCHN_SUFFIX_BLOCKS}-block bounded scan range`);
  const canonicalCheckpointHash = hex32(await call('getblockhash', [anchor.height], `getblockhash at checkpoint height ${anchor.height}`), 'BCHN checkpoint block hash');
  if (canonicalCheckpointHash !== anchor.blockHash) fail('RPC_CHECKPOINT_MISMATCH', 'BCHN canonical checkpoint hash differs from the authenticated checkpoint');
  rpcCheckpointHeader(await call('getblockheader', [anchor.blockHash, true], 'verbose getblockheader at checkpoint'), anchor);
  const announcedTipHash = hex32(await call('getblockhash', [initial.blocks], `getblockhash at height ${initial.blocks}`), `BCHN block hash at height ${initial.blocks}`);
  if (announcedTipHash !== initial.bestBlockHash) fail('RPC_EQUIVOCATION', 'BCHN best block hash disagrees with its canonical height lookup');
  const rawBlocks = []; let parent = anchor.blockHash; let work = anchor.chainwork;
  for (let height = anchor.height + 1; height <= initial.blocks; height += 1) {
    const id = hex32(await call('getblockhash', [height], `getblockhash at height ${height}`), `BCHN block hash at height ${height}`);
    const [rawHeader, verboseHeader, rawBlock] = await Promise.all([
      call('getblockheader', [id, false], `raw getblockheader at height ${height}`),
      call('getblockheader', [id, true], `verbose getblockheader at height ${height}`),
      call('getblock', [id, 0], `getblock at height ${height}`),
    ]);
    const headerBytes = rpcHex(rawHeader, `BCHN header at height ${height}`); const blockBytes = rpcHex(rawBlock, `BCHN block at height ${height}`);
    if (headerBytes.length !== HEADER_BYTES || blockBytes.length < HEADER_BYTES || bytesToHex(blockBytes.subarray(0, HEADER_BYTES)) !== bytesToHex(headerBytes) || displayHash(headerBytes) !== id) fail('RPC_EQUIVOCATION', `BCHN raw header, block, and hash disagree at height ${height}`);
    const parsed = header(headerBytes, BigInt(`0x${anchor.maximumTarget}`)); if (parsed.previousBlockHash !== parent) fail('RPC_EQUIVOCATION', `BCHN raw header parent disagrees at height ${height}`);
    work += parsed.work; rpcHeader(verboseHeader, { expectedHash: id, expectedHeight: height, expectedParent: parent, expectedWork: work }); parent = id; rawBlocks.push(blockBytes);
  }
  if (parent !== initial.bestBlockHash || work !== initial.chainwork) fail('RPC_EQUIVOCATION', 'BCHN raw suffix disagrees with its announced canonical tip or chainwork');
  const final = rpcInfo(await call('getblockchaininfo', [], 'final getblockchaininfo'));
  if (!sameRpcInfo(initial, final)) fail('RPC_REORG_DURING_FETCH', 'BCHN canonical tip changed while the raw suffix was fetched');
  return verifyRawChainSegment({ checkpoint: value.checkpoint, rawBlocks, tip: { blockHash: initial.bestBlockHash, height: initial.blocks, chainwork: initial.chainwork.toString(10) } });
}
