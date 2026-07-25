import assert from 'node:assert/strict';
import test from 'node:test';
import { verifyAndroidLibrary } from './verify-android-library.mjs';

test('Android SDK library source compiles on host JDK with descriptor-only fail-closed native sessions and no network permission', async () => {
  const result = await verifyAndroidLibrary();
  assert.equal(result.schema, 'shield.cash/android-library-host-check/v1');
  assert.match(result.javac.version, /javac/); assert.ok(result.classFiles.length >= 12);
});
