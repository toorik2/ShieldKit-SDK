/* TEST-ONLY: ephemeral keys exercise signature mechanics, never release roots. */
import assert from 'node:assert/strict';
import {
  chmod,
  link,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import {
  generateKeyPairSync,
} from 'node:crypto';
import test from 'node:test';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  createV2Q08HostSignatureEnvelope,
  inspectV2Q08HostSignatureEnvelope,
  loadV2Q08HostPrivateKeyForSignature,
  V2_Q08_HOST_STATEMENT_SCHEMA,
  V2Q08HostEvidenceError,
  verifyV2Q08HostTranscriptForRelease,
} from './q08-host-evidence.mjs';
import { canonicalizeJcs } from './profile-core.mjs';

const authority = (publicKey) => ({
  role: 'clean-host-a',
  signerId: 'test-clean-host-a',
  organizationId: 'test-organization-a',
  independenceDomain: 'test-independence-a',
  publicKey,
});

test('creates and verifies a canonical TEST-ONLY Ed25519 host envelope without a qualification claim', () => {
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({
    format: 'pem',
    type: 'spki',
  }).toString();
  const statement = {
    schema: V2_Q08_HOST_STATEMENT_SCHEMA,
    testOnly: true,
    transcript: 'ephemeral unit evidence',
  };
  const created = createV2Q08HostSignatureEnvelope({
    authority: authority(publicKey),
    privateKey: pair.privateKey,
    statement,
  });
  assert.equal(created.qualification, false);
  assert.equal(created.scope, 'signature-envelope-only');
  const inspected = inspectV2Q08HostSignatureEnvelope({
    authority: authority(publicKey),
    envelopeBytes: created.bytes,
  });
  assert.equal(inspected.qualification, false);
  assert.equal(inspected.scope, 'signature-inspection-only');
  assert.deepEqual(inspected.statement, statement);
});

test('rejects payload tampering, signer substitution, and noncanonical bytes', () => {
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({
    format: 'pem',
    type: 'spki',
  }).toString();
  const created = createV2Q08HostSignatureEnvelope({
    authority: authority(publicKey),
    privateKey: pair.privateKey,
    statement: {
      schema: V2_Q08_HOST_STATEMENT_SCHEMA,
      testOnly: true,
    },
  });
  const tampered = JSON.parse(created.bytes);
  tampered.statement.testOnly = false;
  const canonicalTampered = Buffer.from(canonicalizeJcs(tampered));
  assert.throws(
    () => inspectV2Q08HostSignatureEnvelope({
      authority: authority(publicKey),
      envelopeBytes: canonicalTampered,
    }),
    V2Q08HostEvidenceError,
  );
  const other = generateKeyPairSync('ed25519').publicKey.export({
    format: 'pem',
    type: 'spki',
  }).toString();
  assert.throws(
    () => inspectV2Q08HostSignatureEnvelope({
      authority: authority(other),
      envelopeBytes: created.bytes,
    }),
    /not authentic/u,
  );
  assert.throws(
    () => inspectV2Q08HostSignatureEnvelope({
      authority: authority(publicKey),
      envelopeBytes: Buffer.from(`${created.bytes.toString()}\n`),
    }),
    /exact RFC8785/u,
  );
});

test('private-key loader rejects wrong permissions, links, and authority substitution', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'shieldkit-q08-'));
  t.after(async () => rm(directory, { force: true, recursive: true }));
  const pair = generateKeyPairSync('ed25519');
  const other = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const privateKey = pair.privateKey.export({ format: 'pem', type: 'pkcs8' });
  const keyPath = path.join(directory, 'host-a.pem');
  await writeFile(keyPath, privateKey, { mode: 0o600 });

  await chmod(keyPath, 0o640);
  await assert.rejects(
    () => loadV2Q08HostPrivateKeyForSignature(keyPath, authority(publicKey)),
    (error) => error instanceof V2Q08HostEvidenceError
      && error.code === 'Q08_HOST_PRIVATE_KEY_INVALID',
  );
  await chmod(keyPath, 0o600);

  const symlinkPath = path.join(directory, 'host-a-symlink.pem');
  await symlink(keyPath, symlinkPath);
  await assert.rejects(
    () => loadV2Q08HostPrivateKeyForSignature(symlinkPath, authority(publicKey)),
    (error) => error instanceof V2Q08HostEvidenceError
      && error.code === 'Q08_HOST_PRIVATE_KEY_INVALID',
  );

  const hardLinkPath = path.join(directory, 'host-a-hardlink.pem');
  await link(keyPath, hardLinkPath);
  await assert.rejects(
    () => loadV2Q08HostPrivateKeyForSignature(keyPath, authority(publicKey)),
    (error) => error instanceof V2Q08HostEvidenceError
      && error.code === 'Q08_HOST_PRIVATE_KEY_INVALID',
  );
  await rm(hardLinkPath);

  const otherPublicKey = other.publicKey.export({
    format: 'pem',
    type: 'spki',
  }).toString();
  await assert.rejects(
    () => loadV2Q08HostPrivateKeyForSignature(keyPath, authority(otherPublicKey)),
    (error) => error instanceof V2Q08HostEvidenceError
      && error.code === 'Q08_HOST_PRIVATE_KEY_INVALID',
  );
});

test('rooted verification refuses any caller-forged release root capability', () => {
  assert.throws(
    () => verifyV2Q08HostTranscriptForRelease({
      envelopeBytes: Buffer.from('{}'),
      releaseRoot: Object.freeze({
        cleanHosts: [],
      }),
    }),
    /not a final release root/u,
  );
});
