import { repoPath as vcRepoPath } from '#repo-paths';
// DEFINITIVE net byte model: split-blob coeffs-relocation, all 21 miller_baked chunks.
// MEASURED inputs (from isolated VM + base attribution):
//   - lock saving/coeff = -23.0 B (33B literal out, ~9.8B split machinery in; from bakedg2-blob2)
//   - one-time hash-bind/chunk = ~36 B (DUP HASH256 32B EQUALVERIFY) [already in the -23? blob2 incl it amortized]
//   - op added/chunk: use the isolated measured op for that chunk's coeff count (split+bin2num+hash)
//   - witness/chunk += blob (32B/coeff = 32*np data + ~3B pushdata header)
import { readFileSync } from 'node:fs';
const GEN=vcRepoPath('build/chunked/pairing/generated');
const man=JSON.parse(readFileSync(`${GEN}/manifest_miller_baked.json`,'utf8'));
const OPbase={0:7525344,1:7451661,2:7340187,3:7684628,4:7453071,5:7456179,6:7683868,7:7451705,8:7684153,9:7451808,10:7683903,11:7457103,12:7681520,13:7340503,14:7451569,15:7685820,16:7456384,17:7452027,18:7677310,19:3007307,20:1444747};
const NP={0:48,1:60,2:48,3:48,4:60,5:60,6:48,7:60,8:48,9:60,10:48,11:60,12:48,13:48,14:60,15:48,16:61,17:60,18:48,19:24,20:24};
// MEASURED op added by the split-blob mechanism, fit from isolated runs (op = ~a*N^? ; use the
// table points: 24->33949, 48->87097, 60->120799. The relevant chunks have np in {24,48,60,61}.)
const OP_MECH={24:33949,48:87097,60:120799,61:124000}; // 61 ~ extrapolated
// lock saving/coeff measured -23.0 (net of split machinery, incl amortized one-time hash)
const LOCK_SAVE_PER=23.0;
const STATE_ARG=990, TOWER_BLOB=2285;
const blobWitness=(np)=>32*np+(32*np>255?3:2); // pushdata2 header for >255B
let T={lockSave:0,unlB:0,unlP:0,opP:0,opOver:0};
console.log('ch np  opBase   opMech   opTot    opPad_b opPad_p witB  witP  unlB  unlP  lockSave net');
const BUDGET=8032800;
for(const c of man.chunks){
  const i=c.idx,np=NP[i];
  const opMech=OP_MECH[np]??Math.round(np*2215);
  const opTot=OPbase[i]+opMech;
  const opPadB=Math.ceil(OPbase[i]/800), opPadP=Math.ceil(opTot/800);
  const witB=STATE_ARG+TOWER_BLOB;
  const witP=witB+blobWitness(np);
  const unlB=Math.max(opPadB,witB), unlP=Math.max(opPadP,witP);
  const lockSave=Math.round(np*LOCK_SAVE_PER);
  const net=lockSave-(unlP-unlB);
  if(opTot>BUDGET)T.opOver++;
  T.lockSave+=lockSave;T.unlB+=unlB;T.unlP+=unlP;T.opP+=opTot;
  console.log(`${String(i).padStart(2)} ${String(np).padStart(2)} ${String(OPbase[i]).padStart(8)} ${String(opMech).padStart(7)} ${String(opTot).padStart(8)} ${String(opPadB).padStart(7)} ${String(opPadP).padStart(7)} ${String(witB).padStart(5)} ${String(witP).padStart(5)} ${String(unlB).padStart(5)} ${String(unlP).padStart(5)} ${String(lockSave).padStart(7)} ${String(net).padStart(5)}`);
}
const unlDelta=T.unlP-T.unlB;
console.log(`\nΣ locking saved   = ${T.lockSave} B`);
console.log(`Σ unlock clawback = +${unlDelta} B (op-pad displacement; only low-op tail chunks)`);
console.log(`Σ NET (BN254)     = ${T.lockSave-unlDelta} B  (${T.lockSave-unlDelta>0?'BYTE-POSITIVE':'BYTE-NEGATIVE'})`);
console.log(`chunks over op-budget(8,032,800): ${T.opOver} (Σop=${T.opP.toLocaleString()}, base 147.5M)`);
