// Read-only environment inventory for the Android package gate. It never
// downloads an SDK, starts an emulator, changes an AVD, or contacts a device.
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const candidateTools = Object.freeze(['java', 'javac', 'gradle', 'adb', 'emulator', 'sdkmanager', 'ndk-build']);
const execute = (command, args) => new Promise((resolveRun) => {
  const child = spawn(command, args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'] }); let stdout = ''; let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; }); child.stderr.on('data', (chunk) => { stderr += chunk; }); child.once('error', () => resolveRun({ available: false, output: '' })); child.once('close', (code) => resolveRun({ available: code === 0, output: `${stdout}${stderr}`.trim().slice(0, 4096) }));
});
const which = async (tool) => {
  const found = await execute('sh', ['-c', `command -v ${tool}`]);
  const path = found.available && /^\/[^\r\n]+$/.test(found.output) ? found.output : null;
  return { path, available: path !== null };
};

export async function probeAndroidEnvironment({ outputFile = undefined } = {}) {
  const tools = Object.fromEntries(await Promise.all(candidateTools.map(async (tool) => [tool, await which(tool)])));
  const javaVersion = tools.java.available ? await execute(tools.java.path, ['-version']) : { available: false, output: '' };
  const adbDevices = tools.adb.available ? await execute(tools.adb.path, ['devices', '-l']) : { available: false, output: '' };
  const missing = ['adb', 'emulator', 'sdkmanager', 'gradle', 'ndk-build'].filter((tool) => !tools[tool].available);
  const result = {
    schema: 'shield.cash/android-environment-probe/v1',
    qualification: 'Read-only host inventory only; no APK/emulator/device/native-PF7 execution claim.',
    host: { platform: process.platform, architecture: process.arch, node: process.version },
    tools, javaVersion: javaVersion.output, adbDevices: adbDevices.output,
    androidEnvironmentVariablesPresent: Object.fromEntries(['ANDROID_HOME', 'ANDROID_SDK_ROOT', 'ANDROID_NDK_HOME'].map((key) => [key, Boolean(process.env[key])])),
    status: missing.length === 0 ? 'READY_FOR_LOCAL_ANDROID_BUILD_OR_DEVICE_DISCOVERY' : 'BLOCKED', missing,
  };
  if (outputFile !== undefined) {
    const target = resolve(outputFile); const parent = dirname(target); const staging = `${target}.staging-${process.pid}`;
    await mkdir(parent, { recursive: true });
    try { await writeFile(staging, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx', mode: 0o600 }); await rename(staging, target); } catch (error) { await rm(staging, { force: true }); throw error; }
  }
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  probeAndroidEnvironment(process.argv[2] === undefined ? {} : { outputFile: process.argv[2] }).then((result) => console.log(JSON.stringify({ status: result.status, missing: result.missing }))).catch((error) => { console.error(error.stack ?? error.message); process.exitCode = 1; });
}
