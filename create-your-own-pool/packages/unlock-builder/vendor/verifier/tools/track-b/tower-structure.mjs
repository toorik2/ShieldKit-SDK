import { repoPath as vcRepoPath } from '#repo-paths';
// Inspect the tower-block structure per chunk: fn count, body sizes, id-push sizes,
// and whether the concatenated tower blob is IDENTICAL across chunks of a stage.
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { compileBytecode, splitTowerBytecode } from '../../build/chunked/pairing/_millermath.mjs';
const GEN = vcRepoPath('build/chunked/pairing/generated');
const sha256d = (b) => createHash('sha256').update(createHash('sha256').update(b).digest()).digest();

for (const stage of ['g2check', 'vkx', 'miller_baked', 'finalexp']) {
  const files = readdirSync(GEN).filter((f) => f.startsWith(stage + '_') && f.endsWith('.cash')).sort();
  const blobHashes = new Set();
  let exFns = 0, exBlobLen = 0, exConcatPushLen = 0, exIdLen = 0;
  const fnCounts = new Set();
  for (const f of files) {
    const inline = compileBytecode(readFileSync(`${GEN}/${f}`, 'utf8'));
    const { blocks } = splitTowerBytecode(inline);
    fnCounts.add(blocks.length);
    // concatenated raw body blob (what single-hash would hash over)
    let blob = []; let idLen = 0;
    for (const b of blocks) { blob.push(...b.bodyData); idLen += b.idPush.length; }
    blob = Uint8Array.from(blob);
    blobHashes.add(Buffer.from(sha256d(blob)).toString('hex'));
    exFns = blocks.length; exBlobLen = blob.length; exIdLen = idLen;
    // sum of body sizes + boundary metadata
    const sizes = blocks.map((b) => b.bodyData.length);
    if (f === files[Math.floor(files.length / 2)]) {
      console.log(`\n[${stage}] sample ${f.replace('.cash', '')}: ${blocks.length} fns, blob ${blob.length} B, idPush total ${idLen} B`);
      console.log(`   body sizes: [${sizes.join(', ')}]`);
      console.log(`   min/max/avg body: ${Math.min(...sizes)}/${Math.max(...sizes)}/${Math.round(sizes.reduce((a, c) => a + c, 0) / sizes.length)}`);
    }
  }
  console.log(`[${stage}] chunks=${files.length}  distinct fn-counts across chunks: {${[...fnCounts].join(',')}}  distinct tower-blobs: ${blobHashes.size}`);
  console.log(`   => single-hash const would be ${blobHashes.size === 1 ? 'IDENTICAL' : 'DIFFERENT'} across this stage's chunks`);
}
