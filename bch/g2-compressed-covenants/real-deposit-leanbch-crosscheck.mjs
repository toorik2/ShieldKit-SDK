/* Replays the public real-deposit structural roles through Libauth and LeanBCH. */
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { writeLeanBchInput } from './real-deposit-leanbch-fixture.mjs';

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
const leanRoot = resolve(valueAfter('--lean-root'));
const outputFile = resolve(valueAfter('--output'));
const lakeExecutable = optionalValueAfter('--lake') ?? 'lake';
const xcheckSource = resolve(optionalValueAfter('--xcheck-source') ?? new URL('./leanbch/xcheck_idxN_iter.lean', import.meta.url).pathname);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const keepVectors = args.includes('--keep-vectors');
const parseLean = (output) => {
  const result = /leanVerifyInput=(true|false).*txValid=(true|false).*verifyTokens=(true|false).*leanFullOpCost=(\d+)/.exec(output);
  if (result === null) throw new Error(`unparseable LeanBCH result: ${output}`);
  return {
    accepted: result[1] === 'true',
    transactionValid: result[2] === 'true',
    tokensValid: result[3] === 'true',
    operationCost: Number(result[4]),
  };
};
const git = (arguments_) => execFileSync('git', arguments_, { cwd: leanRoot, encoding: 'utf8', stdio: 'pipe' }).trim();
const leanStatus = git(['status', '--porcelain']);
if (leanStatus !== '') throw new Error(`LeanBCH worktree must be clean; dirty paths: ${leanStatus}`);
const leanCommit = git(['rev-parse', 'HEAD']);
const leanTree = git(['rev-parse', 'HEAD^{tree}']);
const leanManifestSha256 = sha256(await readFile(resolve(leanRoot, 'tooling/manifest.json')));

const directory = await mkdtemp(resolve(tmpdir(), 'shield-real-deposit-leanbch-'));
try {
  const prefix = resolve(directory, 'deposit-complete-real-v1');
  const prepared = await writeLeanBchInput(prefix);
  const rows = prepared.libauth.map((libauth) => {
    const raw = execFileSync(lakeExecutable, ['env', 'lean', '--run', xcheckSource, prefix, String(libauth.inputIndex)], {
      cwd: leanRoot,
      encoding: 'utf8',
      env: { ...process.env, LEANBCH_SECP: 'reject' },
      stdio: 'pipe',
    });
    const lean = parseLean(raw.trim());
    return {
      inputIndex: libauth.inputIndex,
      libauth,
      lean,
      acceptVerdictMatches: libauth.accepted === lean.accepted,
      operationCostMatches: libauth.operationCost === lean.operationCost,
    };
  });
  const result = {
    schema: 'shield.cash/g2-real-deposit-leanbch-crosscheck/v1',
    qualification: 'Real complete deposit structural-role differential only; not complete PF7 role, fee signature, standardness, BCHN relay, or Chipnet evidence.',
    fixture: {
      sha256: prepared.fixtureSha256,
      sourceArtifactSha256: prepared.fixture.provenance.sourceArtifactSha256,
      transactionId: prepared.fixture.provenance.transactionId,
      transactionSha256: prepared.fixture.transaction.sha256,
      transactionBytes: prepared.fixture.transaction.bytes,
      sourceOutputsSha256: prepared.sourceOutputsSha256,
      sourceOutputsBytes: prepared.sourceOutputsWire.length,
    },
    leanBch: {
      root: leanRoot,
      commit: leanCommit,
      tree: leanTree,
      toolingManifestSha256: leanManifestSha256,
      lakeExecutable,
      xcheckSource,
    },
    operationCostAgreementRequired: false,
    rows,
  };
  await writeFile(outputFile, `${JSON.stringify(result, null, 2)}\n`);
  if (rows.length !== 2 || rows.some((row) => !row.acceptVerdictMatches || !row.lean.transactionValid || !row.lean.tokensValid)) {
    throw new Error('LeanBCH acceptance, transaction, or token validity disagreement');
  }
  console.log(JSON.stringify({ outputFile, rows: rows.length, accepted: rows.map(({ lean }) => lean.accepted) }, null, 2));
} finally {
  if (!keepVectors) await rm(directory, { recursive: true, force: true });
}
