import { createHash } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { checkServerIdentity } from 'node:tls';

import { cashAddressToLockingBytecode } from '@bitauth/libauth';

import {
  parseV2ChainConfig,
  V2_CHAIN_CONFIG_NETWORK,
} from './chain-config.mjs';
import { assertV2SecureEndpoint } from './https-transport.mjs';
import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { transactionId } from './transaction-policy.mjs';

export const V2_CHAIN_CLIENT_SCHEMA = 'shieldkit-v2-chain-client-v1';
export const V2_CHAIN_READ_RESPONSE_SCHEMA = 'shieldkit-v2-chain-read-response-v1';
export const V2_CHAIN_READ_RPC_ID = 'shieldkit-v2-chain-read';
export const V2_CHAIN_CLIENT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
export const V2_CANONICAL_HISTORY_REQUEST_SCHEMA = 'shieldkit-v2-canonical-history-request-v1';
export const V2_CANONICAL_HISTORY_PAGE_SCHEMA = 'shieldkit-v2-canonical-history-page-v1';
export const V2_CANONICAL_HISTORY_MAX_ACTIONS = 8;

const TRANSPORT_BRAND = Symbol('V2ReadOnlyChainTransport');
const PRODUCTION_CHAIN_CLIENTS = new WeakSet();
const HEX_32 = /^[0-9a-f]{64}$/;
const HEX = /^(?:[0-9a-f]{2})+$/;
const P2PKH = /^76a914[0-9a-f]{40}88ac$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_MONEY_SATS = 2_100_000_000_000_000n;
const TLS_RANK = Object.freeze({ 'TLSv1.2': 2, 'TLSv1.3': 3 });
const MAX_U32 = 0xffff_ffffn;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const MAX_CANONICAL_HISTORY_CURSOR_CHARS = 4096;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const CANONICAL_HISTORY_SNAPSHOT_DOMAIN = Buffer.from(
  'ShieldKit V2 canonical history v1\0',
  'utf8',
);

export class V2ChainClientError extends Error {
  constructor(code, message, { cause = undefined } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2ChainClientError';
    this.code = code;
  }
}

const fail = (code, message, options) => {
  throw new V2ChainClientError(code, message, options);
};

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('CHAIN_CLIENT_INVALID', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail('CHAIN_CLIENT_INVALID', `${label} has missing or unknown fields`);
  }
  return value;
}

function deepFrozen(value) {
  return (
    Boolean(value)
    && typeof value === 'object'
    && Object.isFrozen(value)
    && Object.values(value).every(
      (child) => !(child && typeof child === 'object') || deepFrozen(child),
    )
  );
}

function hex32(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail('CHAIN_CLIENT_INVALID', `${label} must be lowercase 32-byte hex`);
  }
  return value;
}

function integer(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail('CHAIN_CLIENT_INVALID', `${label} is outside its supported integer range`);
  }
  return value;
}

function decimalSats(value, label) {
  if (
    typeof value !== 'string'
    || !DECIMAL.test(value)
    || BigInt(value) > MAX_MONEY_SATS
  ) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', `${label} must be a canonical BCH amount`);
  }
  return value;
}

function canonicalDecimal(value, maximum, label) {
  if (
    typeof value !== 'string'
    || !DECIMAL.test(value)
    || BigInt(value) > maximum
  ) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', `${label} must be a bounded canonical decimal`);
  }
  return value;
}

function canonicalHistoryCursor(value, label, code = 'CHAIN_CLIENT_INVALID') {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_CANONICAL_HISTORY_CURSOR_CHARS
    || !BASE64URL.test(value)
  ) {
    fail(code, `${label} must be a bounded nonempty base64url cursor`);
  }
  return value;
}

function canonicalJsonBytes(value, label) {
  let parsed;
  try {
    parsed = JSON.parse(value.toString('utf8'));
  } catch (error) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', `${label} is not strict JSON`, { cause: error });
  }
  let canonical;
  try {
    canonical = Buffer.from(canonicalizeJcs(parsed), 'utf8');
  } catch (error) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', `${label} cannot be canonicalized`, { cause: error });
  }
  if (!canonical.equals(value)) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', `${label} must use exact RFC8785/JCS bytes`);
  }
  return parsed;
}

function assertValidatedConfig(value) {
  if (!deepFrozen(value)) {
    fail('CHAIN_CONFIG_REQUIRED', 'chainConfig must be the frozen result of parseV2ChainConfig or loadV2ChainConfig');
  }
  let parsed;
  try {
    parsed = parseV2ChainConfig(value);
  } catch (error) {
    fail('CHAIN_CONFIG_REQUIRED', 'chainConfig is not a validated exact Chipnet configuration', { cause: error });
  }
  if (
    parsed.network !== V2_CHAIN_CONFIG_NETWORK
    || canonicalizeJcs(parsed) !== canonicalizeJcs(value)
  ) {
    fail('CHAIN_CONFIG_REQUIRED', 'chainConfig differs from its validated Chipnet form');
  }
  return parsed;
}

function assertReadTransport(value) {
  if (
    !value
    || value[TRANSPORT_BRAND] !== true
    || typeof value.request !== 'function'
    || typeof value.fixtureOnly !== 'boolean'
  ) {
    fail('CHAIN_TRANSPORT_REQUIRED', 'a branded read-only chain transport is required');
  }
  return value;
}

function brandedTransport(request, fixtureOnly) {
  const value = { fixtureOnly, request };
  Object.defineProperty(value, TRANSPORT_BRAND, { value: true });
  return Object.freeze(value);
}

function normalizeTransportRequest(value) {
  exact(
    value,
    ['body', 'endpoint', 'maxResponseBytes', 'timeoutMs'],
    'chain read transport request',
  );
  if (
    !(value.body instanceof Uint8Array)
    || value.body.length === 0
    || value.body.length > 64 * 1024
    || !Number.isSafeInteger(value.timeoutMs)
    || value.timeoutMs < 1_000
    || value.timeoutMs > 60_000
    || !Number.isSafeInteger(value.maxResponseBytes)
    || value.maxResponseBytes < 1
    || value.maxResponseBytes > V2_CHAIN_CLIENT_MAX_RESPONSE_BYTES
  ) {
    fail('CHAIN_CLIENT_INVALID', 'chain read transport request has unsafe limits');
  }
  return Object.freeze({
    body: Buffer.from(value.body),
    endpoint: assertV2SecureEndpoint(value.endpoint),
    timeoutMs: value.timeoutMs,
    maxResponseBytes: value.maxResponseBytes,
  });
}

async function secureHttpsRead(value) {
  const read = normalizeTransportRequest(value);
  return await new Promise((resolve, reject) => {
    let settled = false;
    let tlsProtocol;
    let peerCertificateSha256;
    const rejectOnce = (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    };
    const request = httpsRequest(
      read.endpoint.url,
      {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-length': String(read.body.length),
          'content-type': 'application/json',
        },
        rejectUnauthorized: true,
        servername: read.endpoint.tls.serverName,
        minVersion: read.endpoint.tls.minVersion,
        checkServerIdentity: (hostname, certificate) => {
          const hostnameError = checkServerIdentity(hostname, certificate);
          if (hostnameError !== undefined) return hostnameError;
          if (!(certificate.raw instanceof Buffer)) {
            return new Error('peer certificate did not include DER bytes');
          }
          const observed = createHash('sha256').update(certificate.raw).digest('hex');
          if (observed !== read.endpoint.tls.certificateSha256) {
            return new Error('peer certificate pin mismatch');
          }
          return undefined;
        },
      },
      (response) => {
        if (
          response.statusCode === undefined
          || response.statusCode < 200
          || response.statusCode > 299
        ) {
          response.resume();
          rejectOnce(new V2ChainClientError(
            response.statusCode !== undefined && response.statusCode >= 300 && response.statusCode < 400
              ? 'CHAIN_REDIRECT_FORBIDDEN'
              : 'CHAIN_HTTP_FAILURE',
            'chain read did not receive an exact successful non-redirect response',
          ));
          return;
        }
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > read.maxResponseBytes) {
            request.destroy();
            rejectOnce(new V2ChainClientError(
              'CHAIN_RESPONSE_TOO_LARGE',
              'chain response exceeded the configured byte limit',
            ));
            return;
          }
          chunks.push(chunk);
        });
        response.once('end', () => {
          if (settled) return;
          if (
            tlsProtocol === undefined
            || peerCertificateSha256 !== read.endpoint.tls.certificateSha256
            || TLS_RANK[tlsProtocol] === undefined
            || TLS_RANK[tlsProtocol] < TLS_RANK[read.endpoint.tls.minVersion]
          ) {
            rejectOnce(new V2ChainClientError(
              'TLS_SECURITY_FAILURE',
              'TLS protocol or pinned certificate evidence was unavailable',
            ));
            return;
          }
          settled = true;
          resolve(Buffer.concat(chunks));
        });
      },
    );
    request.once('socket', (socket) => {
      socket.once('secureConnect', () => {
        if (socket.authorized !== true || socket.authorizationError !== null) {
          request.destroy();
          rejectOnce(new V2ChainClientError(
            'TLS_SECURITY_FAILURE',
            'TLS certificate or hostname authorization failed',
          ));
          return;
        }
        const certificate = socket.getPeerCertificate(true);
        if (!certificate || !(certificate.raw instanceof Buffer)) {
          request.destroy();
          rejectOnce(new V2ChainClientError(
            'TLS_SECURITY_FAILURE',
            'peer certificate bytes were unavailable',
          ));
          return;
        }
        tlsProtocol = socket.getProtocol() ?? undefined;
        peerCertificateSha256 = createHash('sha256')
          .update(certificate.raw)
          .digest('hex');
        if (peerCertificateSha256 !== read.endpoint.tls.certificateSha256) {
          request.destroy();
          rejectOnce(new V2ChainClientError(
            'TLS_CERTIFICATE_PIN_MISMATCH',
            'peer certificate pin differed after authorization',
          ));
        }
      });
    });
    request.setTimeout(read.timeoutMs, () => {
      request.destroy();
      rejectOnce(new V2ChainClientError('CHAIN_TIMEOUT', 'chain read timed out'));
    });
    request.once('error', (error) => {
      rejectOnce(new V2ChainClientError(
        'CHAIN_TRANSPORT_FAILURE',
        'secure chain transport failed closed',
        { cause: error },
      ));
    });
    request.end(read.body);
  });
}

/** Create the pinned-TLS, no-credential, read-only HTTPS transport. */
export function createV2ReadOnlyHttpsTransport() {
  return brandedTransport(async (value) => await secureHttpsRead(value), false);
}

/** Test-only injected read boundary; it cannot expose a broadcast capability. */
export function createV2FixtureOnlyChainTransport(handler) {
  if (typeof handler !== 'function') {
    fail('CHAIN_CLIENT_INVALID', 'fixture chain transport handler must be a function');
  }
  return brandedTransport(
    async (value) => await handler(normalizeTransportRequest(value)),
    true,
  );
}

function rpcRequest(method, params) {
  return Buffer.from(canonicalizeJcs({
    id: V2_CHAIN_READ_RPC_ID,
    jsonrpc: '2.0',
    method,
    params,
  }), 'utf8');
}

function rpcResponse(bytes, expectedOperation) {
  if (!(bytes instanceof Uint8Array)) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'chain transport must return response bytes');
  }
  if (bytes.length === 0 || bytes.length > V2_CHAIN_CLIENT_MAX_RESPONSE_BYTES) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'chain response length is outside the configured limit');
  }
  const value = canonicalJsonBytes(Buffer.from(bytes), 'chain response');
  exact(value, ['error', 'id', 'jsonrpc', 'result'], 'chain RPC response');
  if (
    value.id !== V2_CHAIN_READ_RPC_ID
    || value.jsonrpc !== '2.0'
    || value.error !== null
  ) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'chain RPC response did not match the read request');
  }
  exact(value.result, ['operation', 'result', 'schema'], 'chain RPC result');
  if (
    value.result.schema !== V2_CHAIN_READ_RESPONSE_SCHEMA
    || value.result.operation !== expectedOperation
  ) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'chain response selected an unexpected schema or operation');
  }
  return value.result.result;
}

function parseRawTransaction(value, requestedTxid) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length % 2 !== 0
    || !HEX.test(value)
  ) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'raw transaction must be nonempty lowercase even-length hex');
  }
  if (transactionId(Buffer.from(value, 'hex')) !== requestedTxid) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'raw transaction did not match its requested transaction id');
  }
  return value;
}

function parseCanonicalHistoryRawTransaction(value, requestedTxid, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length % 2 !== 0
    || value.length > 200_000
    || !HEX.test(value)
  ) {
    fail(
      'CHAIN_CLIENT_RESPONSE_INVALID',
      `${label} must be lowercase transaction hex no larger than 100000 bytes`,
    );
  }
  if (transactionId(Buffer.from(value, 'hex')) !== requestedTxid) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', `${label} did not match its transaction id`);
  }
  return value;
}

function parseCanonicalHistoryRequest(value) {
  exact(
    value,
    ['cursor', 'genesisTransactionId', 'instanceId', 'maxActions'],
    'canonical history request',
  );
  const instanceId = hex32(value.instanceId, 'canonical history instanceId');
  const genesisTransactionId = hex32(
    value.genesisTransactionId,
    'canonical history genesisTransactionId',
  );
  if (value.cursor !== null) {
    canonicalHistoryCursor(value.cursor, 'canonical history cursor');
  }
  const maxActions = integer(
    value.maxActions,
    1,
    V2_CANONICAL_HISTORY_MAX_ACTIONS,
    'canonical history maxActions',
  );
  return Object.freeze({
    schema: V2_CANONICAL_HISTORY_REQUEST_SCHEMA,
    instanceId,
    genesisTransactionId,
    cursor: value.cursor,
    maxActions,
  });
}

function parseCanonicalHistoryGenesis(value, requestedGenesisTransactionId) {
  exact(
    value,
    [
      'blockHash',
      'height',
      'initialStateHex',
      'outputIndex',
      'rawTransaction',
      'transactionId',
    ],
    'canonical history genesis',
  );
  const transactionIdValue = hex32(
    value.transactionId,
    'canonical history genesis transactionId',
  );
  if (transactionIdValue !== requestedGenesisTransactionId) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history genesis did not bind the requested transaction id');
  }
  if (typeof value.initialStateHex !== 'string' || !/^[0-9a-f]{256}$/.test(value.initialStateHex)) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history genesis initialStateHex must be lowercase 128-byte hex');
  }
  return Object.freeze({
    transactionId: transactionIdValue,
    rawTransaction: parseCanonicalHistoryRawTransaction(
      value.rawTransaction,
      transactionIdValue,
      'canonical history genesis rawTransaction',
    ),
    height: integer(value.height, 0, Number(MAX_U32), 'canonical history genesis height'),
    blockHash: hex32(value.blockHash, 'canonical history genesis blockHash'),
    outputIndex: integer(value.outputIndex, 0, 0xffff_ffff, 'canonical history genesis outputIndex'),
    initialStateHex: value.initialStateHex,
  });
}

function parseCanonicalHistoryTip(value, confirmationDepth) {
  exact(
    value,
    [
      'actionSequence',
      'blockHash',
      'confirmations',
      'height',
      'outputIndex',
      'stateHex',
      'transactionId',
    ],
    'canonical history tip',
  );
  if (typeof value.stateHex !== 'string' || !/^[0-9a-f]{256}$/.test(value.stateHex)) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history tip stateHex must be lowercase 128-byte hex');
  }
  return Object.freeze({
    transactionId: hex32(value.transactionId, 'canonical history tip transactionId'),
    outputIndex: integer(value.outputIndex, 0, 0xffff_ffff, 'canonical history tip outputIndex'),
    stateHex: value.stateHex,
    actionSequence: canonicalDecimal(
      value.actionSequence,
      MAX_U64,
      'canonical history tip actionSequence',
    ),
    height: integer(value.height, 0, Number(MAX_U32), 'canonical history tip height'),
    blockHash: hex32(value.blockHash, 'canonical history tip blockHash'),
    confirmations: integer(
      value.confirmations,
      confirmationDepth,
      Number.MAX_SAFE_INTEGER,
      'canonical history tip confirmations',
    ),
  });
}

function parseCanonicalHistoryAction(value, index) {
  exact(value, ['action', 'fundingPrevout', 'index'], `canonical history action ${index}`);
  const expectedIndex = String(index);
  if (value.index !== expectedIndex) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history actions must be contiguous from pageStartIndex');
  }
  exact(
    value.action,
    ['blockHash', 'height', 'rawTransaction', 'transactionId'],
    `canonical history action ${index} transaction`,
  );
  exact(
    value.fundingPrevout,
    ['rawTransaction', 'transactionId'],
    `canonical history action ${index} funding prevout`,
  );
  const actionTransactionId = hex32(
    value.action.transactionId,
    `canonical history action ${index} transactionId`,
  );
  const fundingTransactionId = hex32(
    value.fundingPrevout.transactionId,
    `canonical history action ${index} funding transactionId`,
  );
  return Object.freeze({
    index: expectedIndex,
    action: Object.freeze({
      transactionId: actionTransactionId,
      rawTransaction: parseCanonicalHistoryRawTransaction(
        value.action.rawTransaction,
        actionTransactionId,
        `canonical history action ${index} rawTransaction`,
      ),
      height: integer(
        value.action.height,
        0,
        Number(MAX_U32),
        `canonical history action ${index} height`,
      ),
      blockHash: hex32(value.action.blockHash, `canonical history action ${index} blockHash`),
    }),
    fundingPrevout: Object.freeze({
      transactionId: fundingTransactionId,
      rawTransaction: parseCanonicalHistoryRawTransaction(
        value.fundingPrevout.rawTransaction,
        fundingTransactionId,
        `canonical history action ${index} funding rawTransaction`,
      ),
    }),
  });
}

function canonicalHistorySnapshotId({
  instanceId,
  genesis,
  tip,
  actionCount,
  historySha256,
}) {
  const payload = {
    instanceId,
    genesis: {
      transactionId: genesis.transactionId,
      height: genesis.height,
      blockHash: genesis.blockHash,
      outputIndex: genesis.outputIndex,
      initialStateHex: genesis.initialStateHex,
    },
    tip: {
      transactionId: tip.transactionId,
      outputIndex: tip.outputIndex,
      stateHex: tip.stateHex,
      actionSequence: tip.actionSequence,
      height: tip.height,
      blockHash: tip.blockHash,
    },
    actionCount,
    historySha256,
  };
  return createHash('sha256')
    .update(CANONICAL_HISTORY_SNAPSHOT_DOMAIN)
    .update(canonicalizeJcs(payload), 'utf8')
    .digest('hex');
}

function parseCanonicalHistoryPage(value, request, confirmationDepth) {
  exact(
    value,
    [
      'actionCount',
      'actions',
      'genesis',
      'historySha256',
      'instanceId',
      'nextCursor',
      'pageStartIndex',
      'schema',
      'snapshotId',
      'tip',
    ],
    'canonical history page',
  );
  if (
    value.schema !== V2_CANONICAL_HISTORY_PAGE_SCHEMA
    || value.instanceId !== request.instanceId
  ) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history page did not bind its schema and requested instance');
  }
  const genesis = parseCanonicalHistoryGenesis(value.genesis, request.genesisTransactionId);
  const tip = parseCanonicalHistoryTip(value.tip, confirmationDepth);
  const actionCount = canonicalDecimal(value.actionCount, MAX_U32, 'canonical history actionCount');
  if (tip.actionSequence !== actionCount) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history tip actionSequence must equal actionCount');
  }
  const historySha256 = hex32(value.historySha256, 'canonical history historySha256');
  const pageStartIndex = canonicalDecimal(
    value.pageStartIndex,
    MAX_U32,
    'canonical history pageStartIndex',
  );
  const pageStart = Number(pageStartIndex);
  const totalActions = Number(actionCount);
  if (pageStart > totalActions) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history pageStartIndex exceeds actionCount');
  }
  if (!Array.isArray(value.actions) || value.actions.length > request.maxActions) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history page actions exceed requested maximum');
  }
  if (pageStart + value.actions.length > totalActions) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history page actions exceed actionCount');
  }
  const actions = value.actions.map((action, offset) => parseCanonicalHistoryAction(
    action,
    pageStart + offset,
  ));
  const pageEnd = pageStart + actions.length;
  if (value.nextCursor === null) {
    if (pageEnd !== totalActions) {
      fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history nonterminal page must provide nextCursor');
    }
  } else {
    canonicalHistoryCursor(
      value.nextCursor,
      'canonical history nextCursor',
      'CHAIN_CLIENT_RESPONSE_INVALID',
    );
    if (pageEnd === totalActions) {
      fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history terminal page must not provide nextCursor');
    }
    if (actions.length === 0) {
      fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history nonterminal page cannot be empty');
    }
  }
  const snapshotId = hex32(value.snapshotId, 'canonical history snapshotId');
  const expectedSnapshotId = canonicalHistorySnapshotId({
    instanceId: request.instanceId,
    genesis,
    tip,
    actionCount,
    historySha256,
  });
  if (snapshotId !== expectedSnapshotId) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'canonical history snapshotId did not bind the page identity');
  }
  return Object.freeze({
    schema: V2_CANONICAL_HISTORY_PAGE_SCHEMA,
    instanceId: request.instanceId,
    snapshotId,
    genesis,
    tip,
    actionCount,
    historySha256,
    pageStartIndex,
    actions: Object.freeze(actions),
    nextCursor: value.nextCursor,
  });
}

function parsePoolTip(value, confirmationDepth, instanceId) {
  exact(
    value,
    [
      'actionSequence',
      'blockHash',
      'confirmations',
      'height',
      'instanceId',
      'network',
      'state',
      'txid',
      'vout',
    ],
    'authenticated pool-tip observation',
  );
  if (typeof value.state !== 'string' || !/^[0-9a-f]{256}$/.test(value.state)) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'pool-tip state must be lowercase 128-byte hex');
  }
  if (
    value.network !== V2_CHAIN_CONFIG_NETWORK
    || value.instanceId !== instanceId
  ) {
    fail('CHAIN_CLIENT_RESPONSE_INVALID', 'pool-tip observation did not bind the requested Chipnet instance');
  }
  const confirmations = integer(
    value.confirmations,
    confirmationDepth,
    Number.MAX_SAFE_INTEGER,
    'pool-tip confirmations',
  );
  return Object.freeze({
    state: value.state,
    txid: hex32(value.txid, 'pool-tip txid'),
    vout: integer(value.vout, 0, 0xffff_ffff, 'pool-tip vout'),
    actionSequence: integer(
      value.actionSequence,
      0,
      Number.MAX_SAFE_INTEGER,
      'pool-tip actionSequence',
    ),
    height: integer(value.height, 0, Number.MAX_SAFE_INTEGER, 'pool-tip height'),
    blockHash: hex32(value.blockHash, 'pool-tip blockHash'),
    confirmations,
  });
}

function parseWallet(value) {
  exact(
    value,
    ['cashAddress', 'instanceId', 'lockingBytecodeHex'],
    'wallet query',
  );
  if (typeof value.cashAddress !== 'string' || !value.cashAddress.startsWith('bchtest:')) {
    fail('CHAIN_CLIENT_INVALID', 'wallet cashAddress must be a Chipnet cash address');
  }
  if (typeof value.lockingBytecodeHex !== 'string' || !P2PKH.test(value.lockingBytecodeHex)) {
    fail('CHAIN_CLIENT_INVALID', 'wallet lockingBytecodeHex must be canonical P2PKH bytecode');
  }
  const decoded = cashAddressToLockingBytecode(value.cashAddress);
  if (
    typeof decoded === 'string'
    || Buffer.from(decoded.bytecode).toString('hex') !== value.lockingBytecodeHex
  ) {
    fail('CHAIN_CLIENT_INVALID', 'wallet cashAddress does not match its locking bytecode');
  }
  return Object.freeze({
    cashAddress: value.cashAddress,
    instanceId: hex32(value.instanceId, 'wallet query instanceId'),
    lockingBytecodeHex: value.lockingBytecodeHex,
  });
}

function parseWalletUtxos(value, wallet, confirmationDepth) {
  exact(
    value,
    ['canonicalTip', 'cashAddress', 'lockingBytecodeHex', 'utxos'],
    'wallet UTXO observation',
  );
  if (
    value.cashAddress !== wallet.cashAddress
    || value.lockingBytecodeHex !== wallet.lockingBytecodeHex
    || !Array.isArray(value.utxos)
  ) {
    fail(
      'CHAIN_CLIENT_RESPONSE_INVALID',
      'wallet UTXO observation did not bind the requested wallet',
    );
  }
  const seen = new Set();
  const parsed = value.utxos.map((utxo, index) => {
    exact(utxo, ['lockingBytecodeHex', 'token', 'txid', 'valueSats', 'vout'], `wallet UTXO ${index}`);
    const txid = hex32(utxo.txid, `wallet UTXO ${index} txid`);
    const vout = integer(utxo.vout, 0, 0xffff_ffff, `wallet UTXO ${index} vout`);
    if (
      utxo.lockingBytecodeHex !== wallet.lockingBytecodeHex
      || utxo.token !== null
    ) {
      fail('CHAIN_CLIENT_RESPONSE_INVALID', 'wallet UTXO was not a tokenless output for the requested P2PKH address');
    }
    const key = `${txid}:${vout}`;
    if (seen.has(key)) {
      fail('CHAIN_CLIENT_RESPONSE_INVALID', 'wallet UTXO response contains a duplicate outpoint');
    }
    seen.add(key);
    return Object.freeze({
      txid,
      vout,
      valueSats: decimalSats(utxo.valueSats, `wallet UTXO ${index} valueSats`),
      lockingBytecodeHex: wallet.lockingBytecodeHex,
      token: null,
    });
  });
  return Object.freeze({
    canonicalTip: parsePoolTip(
      value.canonicalTip,
      confirmationDepth,
      wallet.instanceId,
    ),
    cashAddress: wallet.cashAddress,
    lockingBytecodeHex: wallet.lockingBytecodeHex,
    utxos: Object.freeze(parsed),
  });
}

class V2ChipnetChainClient {
  #config;
  #transport;

  constructor(config, transport) {
    this.#config = config;
    this.#transport = transport;
    Object.freeze(this);
  }

  async #read(operation, method, params) {
    // Revalidate the complete endpoint on every request, including fixtures.
    const endpoint = assertV2SecureEndpoint(this.#config.endpoint);
    if (endpoint.network !== V2_CHAIN_CONFIG_NETWORK || endpoint.allowRedirects !== false) {
      fail('CHAIN_CONFIG_REQUIRED', 'chain client can only issue pinned no-redirect Chipnet reads');
    }
    const response = await this.#transport.request({
      endpoint,
      body: rpcRequest(method, params),
      timeoutMs: this.#config.requestTimeoutMs,
      maxResponseBytes: V2_CHAIN_CLIENT_MAX_RESPONSE_BYTES,
    });
    return rpcResponse(response, operation);
  }

  /** Fetch exactly one raw BCH transaction and bind it to the requested txid. */
  async fetchTransaction({ transactionId: requestedTxid } = {}) {
    const txid = hex32(requestedTxid, 'transactionId');
    const response = await this.#read('transaction', 'getrawtransaction', [txid, false]);
    return parseRawTransaction(response, txid);
  }

  /** Fetch one current, confirmation-depth-satisfying authenticated pool-tip observation. */
  async fetchAuthenticatedPoolTip({ instanceId } = {}) {
    const id = hex32(instanceId, 'instanceId');
    const response = await this.#read('pool-tip', 'shieldkit_get_pool_tip', [id]);
    return parsePoolTip(response, this.#config.confirmationDepth, id);
  }

  /**
   * Fetch one bounded, pinned-TLS canonical history page for one exact V2
   * instance/genesis pair. The page identity is cryptographically bound before
   * callers can stream raw transactions into the native recovery scanner.
   */
  async fetchCanonicalHistoryPage(value = {}) {
    const request = parseCanonicalHistoryRequest(value);
    const response = await this.#read(
      'canonical-history-page',
      'shieldkit_get_canonical_history_page',
      [request],
    );
    return parseCanonicalHistoryPage(
      response,
      request,
      this.#config.confirmationDepth,
    );
  }

  /** Query only tokenless P2PKH UTXOs for one explicit Chipnet funding address. */
  async queryWalletUtxos(value = {}) {
    const wallet = parseWallet(value);
    const response = await this.#read(
      'wallet-utxos',
      'shieldkit_get_wallet_utxos',
      [wallet.cashAddress, wallet.instanceId],
    );
    return parseWalletUtxos(
      response,
      wallet,
      this.#config.confirmationDepth,
    );
  }
}

/**
 * Construct the narrow V2 Chipnet read client. It deliberately exposes no
 * send, broadcast, write, or credential-bearing operation.
 */
export function createV2ChipnetChainClient({ chainConfig, transport } = {}) {
  const config = assertValidatedConfig(chainConfig);
  const selectedTransport = transport === undefined
    ? createV2ReadOnlyHttpsTransport()
    : assertReadTransport(transport);
  const client = new V2ChipnetChainClient(config, selectedTransport);
  if (selectedTransport.fixtureOnly === false) {
    PRODUCTION_CHAIN_CLIENTS.add(client);
  }
  return client;
}

/**
 * Require a chain client created by this module over the production pinned-TLS
 * transport. Structural duck typing is insufficient at the consensus-recovery
 * boundary because a caller-created object could claim an arbitrary best
 * chain and make internally consistent history appear authoritative.
 */
export function assertV2ProductionChainClientCapability(value) {
  if (
    value === null
    || typeof value !== 'object'
    || !PRODUCTION_CHAIN_CLIENTS.has(value)
  ) {
    fail(
      'PRODUCTION_CHAIN_CLIENT_REQUIRED',
      'a production V2 Chipnet chain client using the pinned-TLS read transport is required',
    );
  }
  return value;
}
