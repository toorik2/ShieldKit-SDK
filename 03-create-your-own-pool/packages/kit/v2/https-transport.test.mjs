import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertV2SecureEndpoint,
  createV2FixtureOnlyTransport,
  createV2HttpsTransport,
} from './https-transport.mjs';
import { fixtureEndpoint } from './v2-test-fixtures.mjs';

test('HTTPS endpoint policy requires CA validation, exact hostname, certificate pin, and no redirects', () => {
  const secure = assertV2SecureEndpoint(fixtureEndpoint());
  assert.equal(secure.url, 'https://node.example.com/rpc');
  for (const mutate of [
    (value) => {
      value.url = 'http://node.example.com/rpc';
    },
    (value) => {
      value.allowRedirects = true;
    },
    (value) => {
      value.tls.rejectUnauthorized = false;
    },
    (value) => {
      value.tls.serverName = 'other.example.com';
    },
    (value) => {
      value.tls.certificateSha256 = 'not-a-pin';
    },
  ]) {
    const value = structuredClone(fixtureEndpoint());
    mutate(value);
    assert.throws(
      () => assertV2SecureEndpoint(value),
      (error) => error?.code === 'UNSAFE_ENDPOINT',
    );
  }
});

test('real and fixture-only transports are visibly distinct and both validate endpoint input before dispatch', async () => {
  const real = createV2HttpsTransport({ timeoutMs: 1 });
  const fixture = createV2FixtureOnlyTransport(async () => ({
    fixture: true,
  }));
  assert.equal(real.fixtureOnly, false);
  assert.equal(fixture.fixtureOnly, true);
  await assert.rejects(
    real.sendRawTransaction({
      rawTxHex: '00',
      endpoint: {
        ...fixtureEndpoint(),
        url: 'http://node.example.com/rpc',
      },
    }),
    (error) => error?.code === 'UNSAFE_ENDPOINT',
  );
  assert.deepEqual(
    await fixture.sendRawTransaction({
      rawTxHex: '00',
      endpoint: fixtureEndpoint(),
    }),
    { fixture: true },
  );
});
