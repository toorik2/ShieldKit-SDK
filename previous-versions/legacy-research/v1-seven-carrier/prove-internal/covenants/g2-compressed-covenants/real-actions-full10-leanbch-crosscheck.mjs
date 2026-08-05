/*
 * Independent, fixture-bound LeanBCH differential for all ten settlement
 * inputs. It consumes complete transaction/source-output fixtures and a clean,
 * caller-selected LeanBCH checkout. Native secp256k1 is mandatory by default:
 * input 9 is a real P2PKH signature and cannot be compared with LeanBCH's
 * reject oracle.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { actionFixturePaths, writeLeanBchInput } from './real-deposit-leanbch-fixture.mjs';

const args = process.argv.slice(2);
const valueAfter = (flag) => {
  const index = args.indexOf(flag);
  if (index < 0 || index + 1 >= args.length) throw new Error(`missing ${flag}`);
  return args[index + 1];
};
const optionalValueAfter = (flag) => {
  const index = args.indexOf(flag);
  return index < 0 ? undefined : valueAfter(flag);
};
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const leanRoot = resolve(valueAfter('--lean-root'));
const outputFile = resolve(valueAfter('--output'));
const lakeExecutable = optionalValueAfter('--lake') ?? 'lake';
const oracle = optionalValueAfter('--oracle') ?? 'native';
const keepVectors = args.includes('--keep-vectors');
if (!['native', 'reject'].includes(oracle)) throw new Error('--oracle must be native or reject');

const git = (arguments_) => execFileSync('git', arguments_, { cwd: leanRoot, encoding: 'utf8', stdio: 'pipe' }).trim();
const parseLean = (output) => {
  const result = /ORACLE=([^ ]+).*leanVerifyInput=(true|false).*txValid=(true|false).*verifyTokens=(true|false).*leanFullOpCost=(\d+)/.exec(output);
  if (result === null) throw new Error(`unparseable LeanBCH result: ${output}`);
  return { oracle: result[1], accepted: result[2] === 'true', transactionValid: result[3] === 'true', tokensValid: result[4] === 'true', operationCost: Number(result[5]) };
};

const leanStatus = git(['status', '--porcelain']);
if (leanStatus !== '') throw new Error(`LeanBCH worktree must be clean; dirty paths: ${leanStatus}`);
const leanCommit = git(['rev-parse', 'HEAD']);
const leanTree = git(['rev-parse', 'HEAD^{tree}']);
const leanManifestSha256 = sha256(await readFile(resolve(leanRoot, 'tooling/manifest.json')));
const runner = resolve(leanRoot, '.lake/build/bin/xcheck_idxN');
if (oracle === 'native') {
  const ffiLibrary = resolve(leanRoot, '.lake/ffi/libsecp256k1.a');
  const ffiShim = resolve(leanRoot, '.lake/ffi/secp256k1_shim.o');
  await access(ffiLibrary, constants.R_OK);
  await access(ffiShim, constants.R_OK);
  // Rebuild from the exact clean checkout. The executable links the staged,
  // pinned FFI archive; its digest is retained in the result below.
  execFileSync(lakeExecutable, ['build', 'xcheck_idxN'], { cwd: leanRoot, encoding: 'utf8', stdio: 'pipe' });
}
await access(runner, constants.X_OK);

const directory = await mkdtemp(resolve(tmpdir(), 'shield-real-actions-full10-leanbch-'));
try {
  const preparedActions = await Promise.all(actionFixturePaths.map(async (fixturePath) => {
    const action = fixturePath.pathname.split('/').at(-1).split('-')[0];
    const prefix = resolve(directory, action);
    const prepared = await writeLeanBchInput(prefix, fixturePath, Array.from({ length: 10 }, (_, inputIndex) => inputIndex));
    return { action, prefix, prepared };
  }));
  const rows = preparedActions.flatMap(({ action, prefix, prepared }) => prepared.libauth.map((libauth) => {
    const raw = execFileSync(runner, [prefix, String(libauth.inputIndex)], {
      cwd: leanRoot, encoding: 'utf8', stdio: 'pipe', env: { ...process.env, LEANBCH_SECP: oracle },
    });
    const lean = parseLean(raw.trim());
    return { action, inputIndex: libauth.inputIndex, libauth, lean, acceptVerdictMatches: libauth.accepted === lean.accepted, operationCostMatches: libauth.operationCost === lean.operationCost };
  }));
  const ffi = oracle === 'native' ? {
    archiveSha256: sha256(await readFile(resolve(leanRoot, '.lake/ffi/libsecp256k1.a'))),
    archiveBytes: (await stat(resolve(leanRoot, '.lake/ffi/libsecp256k1.a'))).size,
    shimSha256: sha256(await readFile(resolve(leanRoot, '.lake/ffi/secp256k1_shim.o'))),
    runnerSha256: sha256(await readFile(runner)),
  } : null;
  const expectedRows = actionFixturePaths.length * 10;
  const rowsWithOracle = rows.filter(({ lean }) => oracle === 'native' ? lean.oracle.startsWith('native(') : lean.oracle === 'reject');
  const result = {
    schema: 'shield.cash/g2-real-actions-full10-leanbch-crosscheck/v1',
    qualification: oracle === 'native'
      ? 'Fixture-bound all-ten-input Libauth versus clean pinned LeanBCH differential with its native BCHN-vendored secp256k1 oracle. Research/conformance only; not BCHN relay, mining, Chipnet inclusion, standardness, or a production claim.'
      : 'Fixture-bound all-ten-input diagnostic using LeanBCH reject oracle. Input 9 is expected to disagree because a real P2PKH signature cannot be verified by that oracle; not a full differential.',
    fixtures: preparedActions.map(({ action, prepared }) => ({ action, sha256: prepared.fixtureSha256, sourceArtifactSha256: prepared.fixture.provenance.sourceArtifactSha256, transactionId: prepared.fixture.provenance.transactionId, transactionSha256: prepared.fixture.transaction.sha256, transactionBytes: prepared.transactionBytes.length, sourceOutputsSha256: prepared.sourceOutputsSha256, sourceOutputsBytes: prepared.sourceOutputsWire.length })),
    leanBch: { root: leanRoot, commit: leanCommit, tree: leanTree, toolingManifestSha256: leanManifestSha256, lakeExecutable, runner, oracle, ffi },
    operationCostAgreementRequired: false,
    rows,
    limitations: [
      'LeanBCH operation-cost agreement is recorded but not required; its full-cost helper is an independently maintained measurement path.',
      'This uses three fixed real proofs, not a 256-proof corpus.',
      'The native secp256k1 oracle has the explicit LeanBCH strict-DER/low-S encoding limitations documented by that project.',
    ],
  };
  const requiredMatches = oracle === 'native' ? rows : rows.filter((row) => row.inputIndex !== 9);
  if (rows.length !== expectedRows || rowsWithOracle.length !== expectedRows || requiredMatches.some((row) => !row.acceptVerdictMatches || !row.lean.transactionValid || !row.lean.tokensValid)) {
    throw new Error('LeanBCH all-input acceptance, transaction, token, or oracle disagreement');
  }
  if (oracle === 'reject' && rows.filter((row) => row.inputIndex === 9).some((row) => row.lean.accepted || row.acceptVerdictMatches)) throw new Error('reject oracle did not expose the expected input-9 signature boundary');
  await writeFile(outputFile, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
  console.log(JSON.stringify({ outputFile, rows: rows.length, oracle, accepted: rows.map(({ lean }) => lean.accepted) }, null, 2));
} finally {
  if (!keepVectors) await rm(directory, { recursive: true, force: true });
}
