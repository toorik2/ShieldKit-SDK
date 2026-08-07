// cli/test-profile.mjs — the unified CLI profile-switch tests (fail-closed assertions).
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, 'scripts/shieldkit.mjs');
const run = (args) => {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 120_000 });
  let parsed = null;
  try { parsed = JSON.parse(r.stdout); } catch { /* non-JSON output */ }
  return { rc: r.status, parsed, stdout: r.stdout.slice(0, 300), stderr: r.stderr.slice(0, 300) };
};
let pass = 0, fail = 0;
const check = (label, cond, detail = '') => {
  if (cond) { pass++; console.log(`PASS ${label}`); }
  else { fail++; console.log(`FAIL ${label} ${detail}`); }
};

// 1. the original surface is unchanged (no --profile)
{
  const r = run(['--version']);
  check('original --version ok', r.rc === 0 && r.parsed?.ok === true && r.parsed?.product === 'ShieldKit-Groth');
}
// 2. --profile pf10 = the original surface
{
  const r = run(['--profile', 'pf10', '--version']);
  check('--profile pf10 --version ok', r.rc === 0 && r.parsed?.ok === true);
}
// 3. the pf6 profile doctor
{
  const r = run(['--profile', 'pf6-a3-direct-v1', 'pool', 'doctor', '--json', '--data-home', process.env.PF6_TEST_DATA_HOME ?? '/tmp/pf6-cli-home3']);
  check('pf6 doctor json', r.rc === 0 && r.parsed?.ok === true && r.parsed?.profile === 'pf6-a3-direct-v1');
  check('pf6 doctor pin', r.parsed?.pin?.scriptBytes === 54671 && r.parsed?.pin?.roles === 6);
}
// 4. unknown profiles fail closed
{
  const r = run(['--profile', 'definitely-not-a-profile', 'pool', 'doctor']);
  check('unknown profile fails closed', r.rc !== 0 && r.parsed?.ok === false && r.parsed?.code === 'UNKNOWN_PROFILE');
}
// 5. --profile without a value fails closed
{
  const r = run(['--profile', '--json', 'pool', 'doctor']);
  check('--profile missing value fails closed', r.rc !== 0 && r.parsed?.code === 'OPTION_VALUE_REQUIRED');
}
// 6. the pf6 profile help
{
  const r = run(['--profile', 'pf6-a3-direct-v1', '--help']);
  check('pf6 profile help', r.rc === 0 && /pool create/.test(r.stdout));
}
// 7. the pf6 profile rejections (missing data-home etc.) fail closed with the profile schema
{
  const r = run(['--profile', 'pf6-a3-direct-v1', 'deposit', '--json']);
  check('pf6 deposit missing args fails closed', r.rc !== 0 && r.parsed?.ok === false);
}
console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
