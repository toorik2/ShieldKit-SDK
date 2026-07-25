// Host-only structural build check for the Android library's pure-Java core.
// It does not claim an Android SDK, Gradle, APK, emulator, or native proof.
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const library = join(root, 'dev/research/android/shieldcash-prover-sdk/sdk');
const source = join(library, 'src/main/java/cash/shield/prover');
const hostTest = join(library, 'src/hostTest/java/cash/shield/prover');
const hash = (value) => createHash('sha256').update(value).digest('hex');
const fail = (message) => { throw new Error(message); };
const run = (command, args) => new Promise((resolveRun, reject) => {
  const child = spawn(command, args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'] }); let stdout = ''; let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; }); child.stderr.on('data', (chunk) => { stderr += chunk; }); child.once('error', reject); child.once('close', (code) => code === 0 ? resolveRun({ stdout, stderr }) : reject(new Error(`${command} exited ${code}: ${stderr}`)));
});
const sources = async () => (await readdir(source)).filter((name) => name.endsWith('.java')).sort().map((name) => join(source, name));
const hostTests = async () => (await readdir(hostTest)).filter((name) => name.endsWith('.java')).sort().map((name) => join(hostTest, name));

export async function verifyAndroidLibrary({ javac = 'javac', outputDirectory = undefined } = {}) {
  const files = await sources(); const tests = await hostTests(); if (files.length < 5 || tests.length < 1) fail('Android library source or host-test set is incomplete');
  const manifest = await readFile(join(library, 'src/main/AndroidManifest.xml'), 'utf8');
  if (/android\.permission\.INTERNET|uses-permission/.test(manifest)) fail('Android library must not request network permission');
  const nativeSource = await readFile(join(source, 'NativePf7Backend.java'), 'utf8');
  if (!nativeSource.includes('System.loadLibrary("shield_pf7")') || !nativeSource.includes('nativeOpenSession') || !nativeSource.includes('FileDescriptor') || !nativeSource.includes('PROCESS_SESSION')) fail('Android library does not require a serialized descriptor-only native PF7 session');
  if (nativeSource.includes('nativeProve(byte[] provingKey') || nativeSource.includes('nativeVerify(byte[] verificationKey')) fail('Android library still passes artifacts across JNI as byte arrays');
  const profileSource = await readFile(join(source, 'ProfileBoundPf7Prover.java'), 'utf8');
  const artifactSource = await readFile(join(source, 'AppPrivateArtifact.java'), 'utf8');
  if (!profileSource.includes('!expected.equals(observed)') || !profileSource.includes('backend.open') || !profileSource.includes('PROCESS_PROOF')) fail('profile binding, session serialization, or local verification is absent');
  if (!artifactSource.includes('Files.isSymbolicLink') || !artifactSource.includes('FileDescriptor') || !artifactSource.includes('artifact hash mismatch')) fail('app-private regular-file artifact checks are absent');
  const temp = outputDirectory === undefined ? await mkdtemp(join(process.cwd(), '.tmp-android-library-')) : resolve(outputDirectory);
  let owned = outputDirectory === undefined;
  try {
    if (!owned) await mkdir(temp, { recursive: false });
    const classes = join(temp, 'classes'); await mkdir(classes);
    const version = await run(javac, ['-version']); await run(javac, ['--release', '17', '-d', classes, ...files, ...tests]); await run('java', [`-Dshield.cash.hostTestDirectory=${join(temp, 'host-artifacts')}`, '-cp', classes, 'cash.shield.prover.HostContractTest']);
    const classFiles = await readdir(classes, { recursive: true });
    const result = { schema: 'shield.cash/android-library-host-check/v1', qualification: 'host-Java source compilation plus fail-closed contract test only; not an Android Gradle build, APK, emulator/device, native PF7 proof, memory, or G4 qualification', javac: { command: javac, version: (version.stdout + version.stderr).trim() }, sourceFiles: files.map((file) => file.slice(root.length + 1)), hostTestFiles: tests.map((file) => file.slice(root.length + 1)), sourceSetSha256: hash(await Promise.all([...files, ...tests].map((file) => readFile(file))).then((parts) => Buffer.concat(parts))), classFiles: classFiles.filter((name) => name.endsWith('.class')).sort(), manifestSha256: hash(manifest) };
    await writeFile(join(temp, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' }); return result;
  } finally { if (owned) await rm(temp, { recursive: true, force: true }); }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const output = process.argv[2];
  verifyAndroidLibrary(output === undefined ? {} : { outputDirectory: output }).then((result) => console.log(JSON.stringify(result))).catch((error) => { console.error(error.stack ?? error.message); process.exitCode = 1; });
}
