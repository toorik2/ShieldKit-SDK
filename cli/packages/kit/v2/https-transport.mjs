import { createHash } from 'node:crypto';
import { request as httpsRequest } from 'node:https';
import { checkServerIdentity } from 'node:tls';

const HEX_32 = /^[0-9a-f]{64}$/;
const DNS_NAME =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const TLS_RANK = Object.freeze({ 'TLSv1.2': 2, 'TLSv1.3': 3 });
const TRANSPORT_BRAND = Symbol('V2HttpsTransport');
const RPC_ID = 'shieldkit-v2-sendrawtransaction';

export class V2HttpsTransportError extends Error {
  constructor(code, message, { ambiguous = false } = {}) {
    super(message);
    this.name = 'V2HttpsTransportError';
    this.code = code;
    this.ambiguous = ambiguous;
  }
}

const fail = (code, message, options) => {
  throw new V2HttpsTransportError(code, message, options);
};

function plain(value, label) {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== 'object' ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('INVALID_TRANSPORT_INPUT', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    fail(
      'INVALID_TRANSPORT_INPUT',
      `${label} has missing or unknown fields`,
    );
  }
  return value;
}

function brandedTransport(sendRawTransaction, fixtureOnly) {
  const value = {
    fixtureOnly,
    sendRawTransaction,
  };
  Object.defineProperty(value, TRANSPORT_BRAND, { value: true });
  return Object.freeze(value);
}

export function assertV2SecureEndpoint(endpoint) {
  exact(endpoint, ['allowRedirects', 'network', 'tls', 'url'], 'endpoint');
  exact(
    endpoint.tls,
    [
      'certificateSha256',
      'minVersion',
      'rejectUnauthorized',
      'serverName',
    ],
    'endpoint.tls',
  );
  let url;
  try {
    url = new URL(endpoint.url);
  } catch {
    fail('UNSAFE_ENDPOINT', 'endpoint URL is invalid');
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.hash ||
    url.search ||
    !['mainnet', 'chipnet'].includes(endpoint.network) ||
    endpoint.allowRedirects !== false ||
    endpoint.tls.rejectUnauthorized !== true ||
    !['TLSv1.2', 'TLSv1.3'].includes(endpoint.tls.minVersion) ||
    endpoint.tls.serverName !== url.hostname ||
    url.hostname !== url.hostname.toLowerCase() ||
    !DNS_NAME.test(url.hostname) ||
    typeof endpoint.tls.certificateSha256 !== 'string' ||
    !HEX_32.test(endpoint.tls.certificateSha256)
  ) {
    fail(
      'UNSAFE_ENDPOINT',
      'endpoint must be a canonical HTTPS DNS name with hostname validation, certificate pinning, and redirects disabled',
    );
  }
  return Object.freeze({
    url: url.toString(),
    network: endpoint.network,
    tls: Object.freeze({
      certificateSha256: endpoint.tls.certificateSha256,
      minVersion: endpoint.tls.minVersion,
      rejectUnauthorized: true,
      serverName: url.hostname,
    }),
    allowRedirects: false,
  });
}

export function assertV2Transport(value) {
  if (
    !value ||
    value[TRANSPORT_BRAND] !== true ||
    typeof value.sendRawTransaction !== 'function' ||
    typeof value.fixtureOnly !== 'boolean'
  ) {
    fail(
      'TRANSPORT_REQUIRED',
      'a branded V2 HTTPS transport or explicit fixture-only transport is required',
    );
  }
  return value;
}

function normalizeTransportOptions(value) {
  exact(value, ['maxResponseBytes', 'timeoutMs'], 'HTTPS transport options');
  if (
    !Number.isSafeInteger(value.timeoutMs) ||
    value.timeoutMs < 1 ||
    value.timeoutMs > 300_000 ||
    !Number.isSafeInteger(value.maxResponseBytes) ||
    value.maxResponseBytes < 1 ||
    value.maxResponseBytes > 16_777_216
  ) {
    fail(
      'INVALID_TRANSPORT_INPUT',
      'HTTPS timeout or response-size limit is outside its safe range',
    );
  }
  return Object.freeze({
    timeoutMs: value.timeoutMs,
    maxResponseBytes: value.maxResponseBytes,
  });
}

function normalizeSend(value) {
  exact(value, ['endpoint', 'rawTxHex'], 'sendRawTransaction');
  if (
    typeof value.rawTxHex !== 'string' ||
    value.rawTxHex.length === 0 ||
    value.rawTxHex.length % 2 !== 0 ||
    !/^[0-9a-f]+$/.test(value.rawTxHex)
  ) {
    fail(
      'INVALID_TRANSPORT_INPUT',
      'rawTxHex must be nonempty lowercase even-length hex',
    );
  }
  return Object.freeze({
    rawTxHex: value.rawTxHex,
    endpoint: assertV2SecureEndpoint(value.endpoint),
  });
}

function parseRpcResponse(body) {
  let value;
  try {
    value = JSON.parse(body);
  } catch {
    fail(
      'RPC_RESPONSE_INVALID',
      'RPC response was not strict JSON',
      { ambiguous: true },
    );
  }
  plain(value, 'RPC response');
  const keys = Object.keys(value).sort();
  const expected = value.jsonrpc === undefined
    ? ['error', 'id', 'result']
    : ['error', 'id', 'jsonrpc', 'result'];
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index]) ||
    (value.jsonrpc !== undefined && value.jsonrpc !== '2.0') ||
    value.id !== RPC_ID ||
    value.error !== null ||
    typeof value.result !== 'string' ||
    !HEX_32.test(value.result)
  ) {
    fail(
      'RPC_RESPONSE_INVALID',
      'RPC response did not contain one unambiguous lowercase transaction id',
      { ambiguous: true },
    );
  }
  return value.result;
}

async function sendWithHttps({ send, options }) {
  const payload = Buffer.from(
    JSON.stringify({
      jsonrpc: '2.0',
      id: RPC_ID,
      method: 'sendrawtransaction',
      params: [send.rawTxHex],
    }),
    'utf8',
  );
  return await new Promise((resolve, reject) => {
    let settled = false;
    let tlsProtocol;
    let peerCertificateSha256;
    const settleReject = (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    };
    const request = httpsRequest(
      send.endpoint.url,
      {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-length': String(payload.length),
          'content-type': 'application/json',
        },
        rejectUnauthorized: true,
        servername: send.endpoint.tls.serverName,
        minVersion: send.endpoint.tls.minVersion,
        checkServerIdentity: (hostname, certificate) => {
          const hostnameError = checkServerIdentity(hostname, certificate);
          if (hostnameError !== undefined) return hostnameError;
          if (!(certificate.raw instanceof Buffer)) {
            const error = new Error('peer certificate did not include DER bytes');
            error.code = 'TLS_CERTIFICATE_MISSING';
            return error;
          }
          const observed = createHash('sha256')
            .update(certificate.raw)
            .digest('hex');
          if (observed !== send.endpoint.tls.certificateSha256) {
            const error = new Error('peer certificate pin mismatch');
            error.code = 'TLS_CERTIFICATE_PIN_MISMATCH';
            return error;
          }
          return undefined;
        },
      },
      (response) => {
        if (
          response.statusCode !== undefined &&
          response.statusCode >= 300 &&
          response.statusCode < 400
        ) {
          response.resume();
          settleReject(
            new V2HttpsTransportError(
              'RPC_REDIRECT_AMBIGUOUS',
              'RPC redirects are forbidden after a send claim',
              { ambiguous: true },
            ),
          );
          return;
        }
        if (response.statusCode !== 200) {
          response.resume();
          settleReject(
            new V2HttpsTransportError(
              'RPC_HTTP_AMBIGUOUS',
              'RPC returned a non-200 response after a send claim',
              { ambiguous: true },
            ),
          );
          return;
        }
        const chunks = [];
        let length = 0;
        response.on('data', (chunk) => {
          length += chunk.length;
          if (length > options.maxResponseBytes) {
            request.destroy();
            settleReject(
              new V2HttpsTransportError(
                'RPC_RESPONSE_TOO_LARGE',
                'RPC response exceeded the configured byte limit',
                { ambiguous: true },
              ),
            );
            return;
          }
          chunks.push(chunk);
        });
        response.once('end', () => {
          if (settled) return;
          try {
            if (
              tlsProtocol === undefined ||
              peerCertificateSha256 === undefined ||
              TLS_RANK[tlsProtocol] === undefined ||
              TLS_RANK[tlsProtocol] <
                TLS_RANK[send.endpoint.tls.minVersion]
            ) {
              fail(
                'TLS_SECURITY_FAILURE',
                'TLS protocol or certificate evidence was unavailable',
                { ambiguous: true },
              );
            }
            const txid = parseRpcResponse(
              Buffer.concat(chunks).toString('utf8'),
            );
            settled = true;
            resolve(
              Object.freeze({
                txid,
                redirected: false,
                tlsProtocol,
                peerCertificateSha256,
              }),
            );
          } catch (error) {
            settleReject(error);
          }
        });
      },
    );
    request.once('socket', (socket) => {
      socket.once('secureConnect', () => {
        if (
          socket.authorized !== true ||
          socket.authorizationError !== null
        ) {
          request.destroy();
          settleReject(
            new V2HttpsTransportError(
              'TLS_SECURITY_FAILURE',
              'TLS certificate or hostname authorization failed',
              { ambiguous: true },
            ),
          );
          return;
        }
        const certificate = socket.getPeerCertificate(true);
        if (!certificate || !(certificate.raw instanceof Buffer)) {
          request.destroy();
          settleReject(
            new V2HttpsTransportError(
              'TLS_SECURITY_FAILURE',
              'peer certificate bytes were unavailable',
              { ambiguous: true },
            ),
          );
          return;
        }
        tlsProtocol = socket.getProtocol() ?? undefined;
        peerCertificateSha256 = createHash('sha256')
          .update(certificate.raw)
          .digest('hex');
        if (
          peerCertificateSha256 !==
          send.endpoint.tls.certificateSha256
        ) {
          request.destroy();
          settleReject(
            new V2HttpsTransportError(
              'TLS_CERTIFICATE_PIN_MISMATCH',
              'peer certificate pin differed after authorization',
              { ambiguous: true },
            ),
          );
        }
      });
    });
    request.setTimeout(options.timeoutMs, () => {
      request.destroy();
      settleReject(
        new V2HttpsTransportError(
          'RPC_TIMEOUT_AMBIGUOUS',
          'RPC timed out after a durable send claim',
          { ambiguous: true },
        ),
      );
    });
    request.once('error', (error) => {
      if (settled) return;
      const code =
        error?.code === 'TLS_CERTIFICATE_PIN_MISMATCH'
          ? 'TLS_CERTIFICATE_PIN_MISMATCH'
          : 'HTTPS_TRANSPORT_FAILURE';
      settleReject(
        new V2HttpsTransportError(
          code,
          'HTTPS transport failed closed during the claimed send',
          { ambiguous: true },
        ),
      );
    });
    request.end(payload);
  });
}

export function createV2HttpsTransport({
  timeoutMs = 15_000,
  maxResponseBytes = 1_048_576,
} = {}) {
  const options = normalizeTransportOptions({
    timeoutMs,
    maxResponseBytes,
  });
  return brandedTransport(
    async (value) =>
      await sendWithHttps({ send: normalizeSend(value), options }),
    false,
  );
}

/**
 * Test-only injection boundary. It is intentionally named and branded as a
 * fixture so it cannot be mistaken for the real TLS transport.
 */
export function createV2FixtureOnlyTransport(handler) {
  if (typeof handler !== 'function') {
    fail(
      'INVALID_TRANSPORT_INPUT',
      'fixture-only transport handler must be a function',
    );
  }
  return brandedTransport(
    async (value) => await handler(normalizeSend(value)),
    true,
  );
}
