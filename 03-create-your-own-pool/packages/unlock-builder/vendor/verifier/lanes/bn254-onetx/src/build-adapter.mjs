import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join, resolve } from 'node:path';

import { makeFileRef, writeCandidateBundle } from '../../../packages/build/src/index.mjs';
import { readBuildProfile, sanitizeLegacyEnvironment, toLegacyEnvironment } from './build-profile.mjs';

export const validateBuild = (build) => {
  for (const field of ['entrypoint', 'fixture']) {
    if (typeof build[field] !== 'string' || build[field].length === 0) {
      throw new Error(`BN254 one-tx build.${field} must be a non-empty repository path`);
    }
  }
  readBuildProfile(build.profile);
  if (build.fixedG2Static !== undefined && typeof build.fixedG2Static !== 'boolean') {
    throw new Error('BN254 one-tx build.fixedG2Static must be boolean when supplied');
  }
  if (build.pairfoldTopology !== undefined
    && build.pairfoldTopology !== 6
    && build.pairfoldTopology !== 7
    && build.pairfoldTopology !== 8) {
    throw new Error('BN254 one-tx build.pairfoldTopology must be 6, 7, or 8 when supplied');
  }
  if (build.structuralRoleCount !== undefined && build.structuralRoleCount !== 3) {
    throw new Error('BN254 one-tx build.structuralRoleCount must be exactly 3 when supplied');
  }
  if (build.shieldAdapter !== undefined) {
    if (build.shieldAdapter === null || typeof build.shieldAdapter !== 'object'
        || Array.isArray(build.shieldAdapter)
        || Object.keys(build.shieldAdapter).sort().join('\0') !== 'path\0sha256'
        || typeof build.shieldAdapter.path !== 'string'
        || !build.shieldAdapter.path.startsWith('/')
        || typeof build.shieldAdapter.sha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(build.shieldAdapter.sha256)) {
      throw new Error('BN254 shieldAdapter must contain an absolute path and lowercase SHA256');
    }
  }
  if (build.structuralRoleCount === 3) {
    if (build.shieldActionPacket === null || typeof build.shieldActionPacket !== 'object'
        || Array.isArray(build.shieldActionPacket)
        || Object.keys(build.shieldActionPacket).sort().join('\0') !== 'path\0sha256'
        || typeof build.shieldActionPacket.path !== 'string'
        || !build.shieldActionPacket.path.startsWith('/')
        || typeof build.shieldActionPacket.sha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(build.shieldActionPacket.sha256)) {
      throw new Error('BN254 ten-input build requires shieldActionPacket with absolute path and lowercase SHA256');
    }
    if (
      build.shieldActionPacketAbi !== 'scar-v1'
      && build.shieldActionPacketAbi !== 'sda2-v2-direct'
    ) {
      throw new Error(
        'BN254 ten-input build requires shieldActionPacketAbi scar-v1 or sda2-v2-direct',
      );
    }
  } else if (build.shieldActionPacket !== undefined) {
    throw new Error('BN254 build.shieldActionPacket requires structuralRoleCount=3');
  } else if (build.shieldActionPacketAbi !== undefined) {
    throw new Error('BN254 build.shieldActionPacketAbi requires structuralRoleCount=3');
  }
  if (build.terminal !== undefined) {
    if (build.terminal === null || typeof build.terminal !== 'object' || Array.isArray(build.terminal)) {
      throw new Error('BN254 one-tx build.terminal must be an object when supplied');
    }
    const terminalKeys = Object.keys(build.terminal).sort();
    const requiredTerminalKeys = ['bqReserveBytes', 'bqResidualNoFuel', 'densDropBytes', 'frobFuse', 'wSelector'];
    if (terminalKeys.join('\0') !== requiredTerminalKeys.join('\0')) {
      throw new Error(`BN254 one-tx build.terminal must define exactly ${requiredTerminalKeys.join(', ')}`);
    }
    for (const field of ['frobFuse', 'wSelector', 'bqResidualNoFuel']) {
      if (typeof build.terminal[field] !== 'boolean') {
        throw new Error(`BN254 one-tx build.terminal.${field} must be boolean`);
      }
    }
    for (const field of ['densDropBytes', 'bqReserveBytes']) {
      if (!Number.isInteger(build.terminal[field]) || build.terminal[field] < 0 || build.terminal[field] > 10_000) {
        throw new Error(`BN254 one-tx build.terminal.${field} must be an integer in [0, 10000]`);
      }
    }
  }
  if (build.fixedG2Static === true) {
    if (build.profile.layout.windowSize !== 13) {
      throw new Error('fixed-G2 static build requires the K=13 window profile');
    }
    const fragments = build.profile.layout.stripedFragments;
    const topology = build.pairfoldTopology ?? 7;
    if (topology === 6 && fragments !== 4) {
      throw new Error('PairFold-6 fixed-G2 static build requires stripedFragments=4');
    }
    if (topology === 7 && fragments !== 5) {
      throw new Error('PairFold-7 fixed-G2 static build requires stripedFragments=5');
    }
    if (topology === 8 && fragments !== 6) {
      throw new Error('PairFold-8 fixed-G2 static build requires stripedFragments=6');
    }
    if (typeof build.inputValidationFixture !== 'string' || build.inputValidationFixture.length === 0) {
      throw new Error('fixed-G2 static build requires build.inputValidationFixture');
    }
    if (build.runtimeCorpus !== undefined) {
      if (build.runtimeCorpus === null || typeof build.runtimeCorpus !== 'object' || Array.isArray(build.runtimeCorpus)) {
        throw new Error('fixed-G2 static build.runtimeCorpus must be an object when supplied');
      }
      const keys = Object.keys(build.runtimeCorpus).sort();
      if (keys.join('\0') !== 'extraMultiproofIndices\0worstCase') {
        throw new Error('fixed-G2 static build.runtimeCorpus must define exactly extraMultiproofIndices and worstCase');
      }
      const indices = build.runtimeCorpus.extraMultiproofIndices;
      if (!Array.isArray(indices) || indices.length === 0 || indices.some((index) => !Number.isInteger(index) || index < 0)) {
        throw new Error('fixed-G2 static build.runtimeCorpus.extraMultiproofIndices must be a non-empty array of non-negative integers');
      }
      if (new Set(indices).size !== indices.length) throw new Error('fixed-G2 static build.runtimeCorpus.extraMultiproofIndices must be unique');
      if (typeof build.runtimeCorpus.worstCase !== 'boolean') throw new Error('fixed-G2 static build.runtimeCorpus.worstCase must be boolean');
    }
  }
};

export const buildCandidate = ({ candidate, candidatePath, runId, outDir, repoRoot, sourceCommit }) => {
  validateBuild(candidate.build);
  const buildDir = resolve(outDir, 'build');
  const generatedDir = resolve(outDir, 'generated');
  const tmpDir = resolve(outDir, 'tmp');
  const processTmpDir = mkdtempSync(join(tmpdir(), 'vc-tsx-'));
  mkdirSync(buildDir, { recursive: true });
  mkdirSync(generatedDir, { recursive: true });
  mkdirSync(tmpDir, { recursive: true });

  const tsx = resolve(repoRoot, 'harness/node_modules/.bin/tsx');
  const entrypoint = resolve(repoRoot, candidate.build.entrypoint);
  const fixture = resolve(repoRoot, candidate.build.fixture);
  const fixedG2Static = candidate.build.fixedG2Static === true;
  const inputValidationFixture = fixedG2Static
    ? resolve(repoRoot, candidate.build.inputValidationFixture)
    : undefined;
  if (inputValidationFixture !== undefined && !existsSync(inputValidationFixture)) {
    throw new Error(`fixed-G2 static input-validation fixture is absent: ${inputValidationFixture}`);
  }
  const environment = {
    ...sanitizeLegacyEnvironment(process.env),
    ...toLegacyEnvironment(
      candidate.build.profile,
      fixture,
      candidate.build.shieldAdapter,
    ),
    C7_TMP: buildDir,
    C7_GEN: generatedDir,
    TMPDIR: processTmpDir,
    CASHC_ROOT: resolve(repoRoot, 'vendor/cashc-resched/packages/cashc'),
    LEANBCH_ROOT: process.env.LEANBCH_ROOT ?? (
      existsSync(resolve(repoRoot, '.vc/deps/LeanBCH'))
        ? resolve(repoRoot, '.vc/deps/LeanBCH')
        : resolve(repoRoot, '..', 'LeanBCH')
    ),
    PATH: `${resolve(repoRoot, 'harness/node_modules/.bin')}${delimiter}${process.env.PATH ?? ''}`,
    ...(fixedG2Static ? {
      C7_PROJECTED_BQ_7: '1',
      C7_FIXED_G2_TABLE: '1',
      // Compact doubles + projective-normalized adds. The offline normalized
      // S-Z trajectory regenerates the scaled quotient so every omitted c0
      // remains authenticated against the live fixed lines.
      C7_FIXED_G2_COMPACT: '1',
      C7_FIXED_G2_NORMALIZED_ADDS: '1',
      // Dens-rich: FS binds hash256(VK G2 limbs) instead of 448 B (a1-vkdig).
      C7_VK_DIGEST: '1',
      // Dens-rich: L17 wsel class as 1 B in resBE (not BE32) — FS layout match offline.
      C7_WSEL_U8: '1',
      // C7_FIXED_G2_XONLY is research-ready for PF7 windows (tables ~11.4k vs
      // ~18.8k) but the shared composed body still references normalized limb
      // names (gx0/…) — do not enable until xOnlyStepSource is fully wired.
      // Composed w=2 PairFold-7 route: drop intermediate odd Fp12 anchors in
      // exchange for a larger terminal BQ, for a net ~9k scored-byte cut.
      // Executors stay on the fixed-G2 static body; genesis/terminal bind the
      // mixed Fiat-Shamir transcript. Direct/self-carried terminal keeps the
      // enlarged BQ under the 10k unlocking limit (full-P2SH did not).
      C7_COMPOSED_P2SH: '1',
      C7_COMPOSED_DIRECT_TERMINAL: '1',
      C7_PAIRFOLD_TOPOLOGY: String(candidate.build.pairfoldTopology ?? 7),
      ...(candidate.build.structuralRoleCount === 3 ? {
        C7_STRUCTURAL_ROLE_COUNT: '3',
        C7_SHIELD_ACTION_PACKET_FILE: candidate.build.shieldActionPacket.path,
        C7_SHIELD_ACTION_PACKET_SHA256: candidate.build.shieldActionPacket.sha256,
        C7_SHIELD_ACTION_PACKET_ABI: candidate.build.shieldActionPacketAbi,
      } : {}),
      ...(candidate.build.idealVariant ? { C7_IDEAL_VARIANT: String(candidate.build.idealVariant) } : {}),
      ...(candidate.build.scalarEndpoint === true ? { C7_SCALAR_ENDPOINT: '1' } : {}),
      // dens-rich: densFuel DROP dens-positive when densFuel remains after dens knife
      ...(candidate.build.densFuelDrop === true ? { C7_DENSFUEL_DROP: '1' } : {}),
      ...(candidate.build.terminal ? {
        // Keep every terminal layout and density choice in the manifest. These
        // override a caller environment only after that environment is stripped.
        TERMINAL_FROB_FUSE: candidate.build.terminal.frobFuse ? '1' : '0',
        TERMINAL_W_SELECTOR: candidate.build.terminal.wSelector ? '1' : '0',
        C7_SCALAR_TERM_DENS_DROP: String(candidate.build.terminal.densDropBytes),
        C7_SCALAR_BQ_RESERVE: String(candidate.build.terminal.bqReserveBytes),
        C7_SCALAR_BQ_NO_FUEL: candidate.build.terminal.bqResidualNoFuel ? '1' : '0',
      } : {}),

      C7_ZBITS_GB3: './normalized-gb3.mjs',
      C7_SZ_MODULE: './mixed-sz.mjs',
      C7_FIXED_G2_UNLOCK_TABLE: '1',
      // PF7 dens-rich default (5 exec). PF6 dens-rich uses 4 natural carriers (0,0,0,0 = full unlock tables).
      C7_FIXED_G2_WITNESS_TABLE_BYTES: candidate.build.fixedG2WitnessTableBytes
        ?? (Number(candidate.build.pairfoldTopology ?? 7) === 6 ? '0,0,0,0' : '0,1536,2460,2427,2304'),
      C7_SELF_CARRIED_TERMINAL: '1',
      TERMINAL_FUSION9: '1',
      TERMINAL_REUSE_ZPOWERS: '1',
      TERMINAL_CANON_ZPROLOGUE: '1',
      TERMINAL_FULL_OPT: '1',
    } : {}),
  };
  let processResult;
  try {
    processResult = spawnSync(tsx, [entrypoint], {
      cwd: repoRoot,
      env: environment,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
  } finally {
    rmSync(processTmpDir, { recursive: true, force: true });
  }
  const log = [processResult.stdout ?? '', processResult.stderr ?? ''].filter(Boolean).join('\n');
  writeFileSync(resolve(outDir, 'build.log'), log);
  if (processResult.error) throw processResult.error;
  if (processResult.status !== 0) throw new Error(`BN254 one-tx build failed with exit ${processResult.status}; see ${resolve(outDir, 'build.log')}`);

  const resultPath = resolve(buildDir, 'result.json');
  if (!existsSync(resultPath)) throw new Error(`BN254 one-tx build did not emit ${resultPath}`);
  const buildResult = JSON.parse(readFileSync(resultPath, 'utf8'));
  if (buildResult.built !== true || buildResult.gateOk !== true) {
    throw new Error(`BN254 one-tx build is not real-gate green: ${JSON.stringify(buildResult)}`);
  }
  if (candidate.build.structuralRoleCount === 3) {
    throw new Error('bounded ten-role verifier-context output has unevaluated packet/state/fee roles and must not produce a CandidateBundle');
  }
  let vectorPaths = {};
  if (fixedG2Static) {
    const offsubDir = resolve(outDir, 'offsubgroup');
    const offsubGenerated = resolve(outDir, 'offsubgroup-generated');
    const redteamDir = resolve(outDir, 'input-redteam');
    const runtimeCorpus = candidate.build.runtimeCorpus;
    mkdirSync(offsubDir, { recursive: true });
    mkdirSync(offsubGenerated, { recursive: true });
    const offsubProcessTmpDir = mkdtempSync(join(tmpdir(), 'vc-tsx-offsub-'));
    let offsubResult;
    try {
      offsubResult = spawnSync(tsx, [entrypoint], {
        cwd: repoRoot,
        env: {
          ...environment,
          TMPDIR: offsubProcessTmpDir,
          ELIG_INSTANCE: 'file',
          ELIG_FILE: inputValidationFixture,
          C7_TMP: offsubDir,
          C7_GEN: offsubGenerated,
        },
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
      });
    } finally {
      rmSync(offsubProcessTmpDir, { recursive: true, force: true });
    }
    const offsubLog = [offsubResult.stdout ?? '', offsubResult.stderr ?? ''].filter(Boolean).join('\n');
    writeFileSync(resolve(outDir, 'offsubgroup-build.log'), offsubLog);
    if (offsubResult.error) throw offsubResult.error;
    if (offsubResult.status !== 0) throw new Error(`fixed-G2 off-subgroup build failed with exit ${offsubResult.status}; see ${resolve(outDir, 'offsubgroup-build.log')}`);
    const offsubResultPath = resolve(offsubDir, 'result.json');
    if (!existsSync(offsubResultPath)) throw new Error(`fixed-G2 off-subgroup build did not emit ${offsubResultPath}`);
    const offsubBuild = JSON.parse(readFileSync(offsubResultPath, 'utf8'));
    const terminalRow = offsubBuild.manual?.find((row) => row.name === 'terminal');
    if (offsubBuild.gateOk !== false || terminalRow?.accepts !== false) {
      throw new Error(`fixed-G2 off-subgroup vector did not reject at the terminal: ${JSON.stringify(offsubBuild.manual)}`);
    }
    const primaryInputs = JSON.parse(readFileSync(resolve(buildDir, 'inputs_dump.json'), 'utf8'));
    const assertSameLockings = (variantDir, label) => {
      const variant = JSON.parse(readFileSync(resolve(variantDir, 'inputs_dump.json'), 'utf8'));
      if (!Array.isArray(variant) || variant.length !== primaryInputs.length) {
        throw new Error(`${label} did not emit the expected ${primaryInputs.length}-input run`);
      }
      for (const [index, item] of variant.entries()) {
        if (item?.lock !== primaryInputs[index]?.lock) {
          throw new Error(`${label} changes locking bytecode at input ${index}; it is not a runtime proof replay`);
        }
      }
    };
    const runAcceptedVariant = (name, selector) => {
      const variantDir = resolve(outDir, name);
      const variantGenerated = resolve(outDir, `${name}-generated`);
      mkdirSync(variantDir, { recursive: true });
      mkdirSync(variantGenerated, { recursive: true });
      const variantTmp = mkdtempSync(join(tmpdir(), `vc-tsx-${name}-`));
      let variantResult;
      try {
        const variantEnvironment = {
          ...environment,
          TMPDIR: variantTmp,
          C7_TMP: variantDir,
          C7_GEN: variantGenerated,
          ELIG_INSTANCE: selector.instance,
          ELIG_IDX: String(selector.index ?? 0),
        };
        delete variantEnvironment.ELIG_FILE;
        variantResult = spawnSync(tsx, [entrypoint], {
          cwd: repoRoot,
          env: variantEnvironment,
          encoding: 'utf8',
          maxBuffer: 64 * 1024 * 1024,
        });
      } finally {
        rmSync(variantTmp, { recursive: true, force: true });
      }
      const variantLog = [variantResult.stdout ?? '', variantResult.stderr ?? ''].filter(Boolean).join('\n');
      writeFileSync(resolve(outDir, `${name}-build.log`), variantLog);
      if (variantResult.error) throw variantResult.error;
      if (variantResult.status !== 0) throw new Error(`${name} build failed with exit ${variantResult.status}; see ${resolve(outDir, `${name}-build.log`)}`);
      const variantResultPath = resolve(variantDir, 'result.json');
      if (!existsSync(variantResultPath)) throw new Error(`${name} build did not emit ${variantResultPath}`);
      const variantBuild = JSON.parse(readFileSync(variantResultPath, 'utf8'));
      if (variantBuild.built !== true || variantBuild.gateOk !== true) {
        throw new Error(`${name} is not a real-gate-green runtime proof: ${JSON.stringify(variantBuild)}`);
      }
      assertSameLockings(variantDir, name);
      return variantDir;
    };
    const extraValidDirs = (runtimeCorpus?.extraMultiproofIndices ?? []).map((index, ordinal) =>
      runAcceptedVariant(`extra-valid-${ordinal}`, { instance: 'multiproof', index }));
    const worstCaseDir = runtimeCorpus?.worstCase === true
      ? runAcceptedVariant('worst-case', { instance: 'worstcase' })
      : undefined;
    const redteamEntrypoint = resolve(repoRoot, 'lanes/bn254-onetx/src/c7/run-input-redteam.ts');
    const redteam = spawnSync(tsx, [redteamEntrypoint,
      '--honest', buildDir,
      '--offsub', offsubDir,
      '--fixture', fixture,
      ...extraValidDirs.flatMap((dir) => ['--extra', dir]),
      ...(worstCaseDir === undefined ? [] : ['--worst', worstCaseDir]),
      '--out', redteamDir,
    ], {
      cwd: repoRoot,
      env: environment,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
    const redteamLog = [redteam.stdout ?? '', redteam.stderr ?? ''].filter(Boolean).join('\n');
    writeFileSync(resolve(outDir, 'input-redteam.log'), redteamLog);
    if (redteam.error) throw redteam.error;
    if (redteam.status !== 0) throw new Error(`fixed-G2 input red-team failed with exit ${redteam.status}; see ${resolve(outDir, 'input-redteam.log')}`);
    const vectorPath = resolve(redteamDir, 'vectors.json');
    const redteamPath = resolve(redteamDir, 'input-redteam.json');
    if (!existsSync(vectorPath) || !existsSync(redteamPath)) throw new Error('fixed-G2 input red-team emitted incomplete evidence');
    vectorPaths = {
      vectors: vectorPath,
      'input-redteam': redteamPath,
      'offsubgroup-result': offsubResultPath,
      'input-redteam-log': resolve(outDir, 'input-redteam.log'),
    };
  }
  const rolePaths = {
    result: resultPath,
    inputs: resolve(buildDir, 'inputs_dump.json'),
    transaction: resolve(buildDir, 'c7_candidate_tx.hex'),
    'source-outputs': resolve(buildDir, 'c7_candidate_srcouts.hex'),
    'boundary-parts': resolve(buildDir, 'boundary_parts.json'),
    'op-margin': resolve(buildDir, 'c7_opmargin.json'),
    'build-log': resolve(outDir, 'build.log'),
    ...vectorPaths,
  };
  const files = Object.fromEntries(Object.entries(rolePaths)
    .filter(([, path]) => existsSync(path))
    .map(([role, path]) => [role, makeFileRef(repoRoot, path)]));

  return writeCandidateBundle({
    repoRoot,
    candidate,
    candidatePath,
    files,
    runId,
    sourceCommit,
    outDir,
    buildResult,
  });
};
