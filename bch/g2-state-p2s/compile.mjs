import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const cashcRoot = process.env.CASHC_ROOT;
if (!cashcRoot) throw new Error('CASHC_ROOT must name the pinned cashc package root');
const cashc = await import(pathToFileURL(resolve(cashcRoot, 'dist/index.js')).href);
if (cashc.version !== '0.14.0-next.1') throw new Error(`wrong cashc: ${cashc.version}`);
const source = await readFile(resolve(here, 'ShieldStateV1.cash'), 'utf8');
const artifact = cashc.compileString(source, { optimizeFor: 'size' });
const script = cashc.utils.scriptToBytecode(cashc.utils.asmToScript(artifact.bytecode));
console.log(JSON.stringify({
  compiler: cashc.version,
  contract: artifact.contractName,
  executableBytecodeBytes: script.length,
  executableBytecodeHex: Buffer.from(script).toString('hex'),
  disassembly: artifact.bytecode,
  abi: artifact.abi,
  constructorInputs: artifact.constructorInputs,
}, null, 2));
