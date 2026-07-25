import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { probeAndroidEnvironment } from './probe-android-environment.mjs';

test('Android environment probe writes a bounded, secret-free inventory', async () => {
  const directory = await mkdtemp(path.join(process.cwd(), '.tmp-android-environment-'));
  try {
    const file = path.join(directory, 'probe.json'); const result = await probeAndroidEnvironment({ outputFile: file });
    assert.equal(result.schema, 'shield.cash/android-environment-probe/v1'); assert.equal(typeof result.tools.java.available, 'boolean'); assert.equal(JSON.parse(await readFile(file, 'utf8')).status, result.status); assert.equal(JSON.stringify(result).includes('ANDROID_HOME='), false);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
