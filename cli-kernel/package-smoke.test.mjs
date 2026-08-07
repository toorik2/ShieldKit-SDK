import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function run(file, args, cwd) {
  return execFileSync(process.execPath, [file, ...args], { cwd, encoding: 'utf8' });
}

test('packed CLI contains its runtime closure and runs without the checkout', () => {
  const temp = mkdtempSync(path.join(os.tmpdir(), 'shieldkit-pack-'));
  try {
    const packed = JSON.parse(execFileSync('npm', ['pack', '--json', '--pack-destination', temp], {
      cwd: ROOT,
      encoding: 'utf8',
    }));
    assert.equal(packed.length, 1);
    const tarball = path.join(temp, packed[0].filename);
    assert.ok(existsSync(tarball));
    execFileSync('tar', ['-xzf', tarball, '-C', temp]);
    const installed = path.join(temp, 'package');
    const bin = path.join(installed, 'cli-kernel/bin/shieldkit.mjs');
    assert.ok(existsSync(path.join(installed, 'cli-kernel/front-controller.mjs')));
    assert.ok(existsSync(path.join(installed, 'cli-kernel/contracts/errors.mjs')));
    assert.match(run(bin, ['--version'], installed), /^shieldkit \S+\n$/);
    assert.match(run(bin, ['--help'], installed), /unified CLI/);
    const designs = JSON.parse(run(bin, ['design', 'list'], installed));
    assert.equal(designs.ok, true);
    assert.equal(designs.result.backendModuleLoaded, false);
    // This is a non-mutating PF10 path and proves the packed contextual command survives.
    assert.match(run(bin, ['--design', 'pf10', 'design', 'doctor', '--help'], installed), /ShieldKit design doctor/);
    const doctor = JSON.parse(run(bin, ['--design', 'pf10', 'design', 'doctor'], installed));
    assert.equal(doctor.ok, true, JSON.stringify(doctor));
    assert.equal(doctor.result.delegated, true);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
