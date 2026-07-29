pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulany.circom";

// PoolActionV2Direct — production-depth relation (TREE_DEPTH=32).
// Public: two 128-bit limbs of SHA256(SDA2 packet).
// Private: counters, note/nullifier Poseidon, Merkle paths, indexed-nullifier
// insert (spend), record commitment + BabyJub note encryption (create).

function DOMAIN_NOTE() { return 2002; }
function DOMAIN_NULLIFIER() { return 2003; }
function DOMAIN_NOTE_LEAF() { return 2010; }
function DOMAIN_NOTE_NODE() { return 2011; }
function DOMAIN_NOTE_EMPTY() { return 2012; }
function DOMAIN_NULLIFIER_LEAF() { return 2020; }
function DOMAIN_NULLIFIER_NODE() { return 2021; }
function DOMAIN_NULLIFIER_EMPTY() { return 2022; }
function DOMAIN_RECORD() { return 2030; }

function NF_TYPE_EMPTY() { return 0; }
function NF_TYPE_MIN() { return 1; }
function NF_TYPE_NORMAL() { return 2; }
function NF_TYPE_MAX() { return 3; }

// Merkle path over Poseidon(domain, left, right) with domain as first input.
template MerklePoseidonDomain(depth, domain) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth]; // 0 = leaf on left, 1 = leaf on right
    signal output root;

    component hashers[depth];
    component muxL[depth];
    component muxR[depth];
    signal level[depth + 1];
    level[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
        muxL[i] = Mux1();
        muxL[i].c[0] <== level[i];
        muxL[i].c[1] <== pathElements[i];
        muxL[i].s <== pathIndices[i];

        muxR[i] = Mux1();
        muxR[i].c[0] <== pathElements[i];
        muxR[i].c[1] <== level[i];
        muxR[i].s <== pathIndices[i];

        hashers[i] = Poseidon(3);
        hashers[i].inputs[0] <== domain;
        hashers[i].inputs[1] <== muxL[i].out;
        hashers[i].inputs[2] <== muxR[i].out;
        level[i + 1] <== hashers[i].out;
    }
    root <== level[depth];
}

// Replace oldLeaf with newLeaf along the same path; verify oldRoot and emit newRoot.
template MerkleUpdateDomain(depth, domain) {
    signal input oldLeaf;
    signal input newLeaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input oldRoot;
    signal output newRoot;

    component oldM = MerklePoseidonDomain(depth, domain);
    oldM.leaf <== oldLeaf;
    for (var i = 0; i < depth; i++) {
        oldM.pathElements[i] <== pathElements[i];
        oldM.pathIndices[i] <== pathIndices[i];
    }
    oldM.root === oldRoot;

    component newM = MerklePoseidonDomain(depth, domain);
    newM.leaf <== newLeaf;
    for (var i = 0; i < depth; i++) {
        newM.pathElements[i] <== pathElements[i];
        newM.pathIndices[i] <== pathIndices[i];
    }
    newRoot <== newM.root;
}

// Poseidon sponge matching JS poseidonSponge(domain, limbs[8])
template RecordCommitmentSponge() {
    signal input limbs[8];
    signal output out;

    component h0 = Poseidon(2);
    h0.inputs[0] <== DOMAIN_RECORD();
    h0.inputs[1] <== limbs[0];

    component h[7];
    signal st[8];
    st[0] <== h0.out;
    for (var i = 0; i < 7; i++) {
        h[i] = Poseidon(3);
        h[i].inputs[0] <== DOMAIN_RECORD();
        h[i].inputs[1] <== st[i];
        h[i].inputs[2] <== limbs[i + 1];
        st[i + 1] <== h[i].out;
    }
    out <== st[7];
}

template PoolActionV2Direct(treeDepth) {
    // Public
    signal input publicInput0;
    signal input publicInput1;

    signal input limb0;
    signal input limb1;

    signal input kind;

    signal input preNoteCount;
    signal input preNullifierCount;
    signal input preReserve;
    signal input preActionSequence;
    signal input preMaximumLiveNotes;
    signal input postNoteCount;
    signal input postNullifierCount;
    signal input postReserve;
    signal input postActionSequence;

    signal input profileIdLo;
    signal input profileIdHi;
    signal input instanceIdLo;
    signal input instanceIdHi;
    signal input denomination;

    // Primary note (deposit create / spend spent)
    signal input authority;
    signal input rho;
    signal input r;
    signal input sk;
    signal input cm;
    signal input nf;
    signal input recordCommitment;
    signal input outputNoteLeaf;
    signal input publicNullifier;

    // Transfer create note
    signal input createAuthority;
    signal input createRho;
    signal input createR;
    signal input createCm;

    // Note tree
    signal input preNoteRoot;
    signal input postNoteRoot;
    signal input notePathElements[treeDepth];
    signal input notePathIndices[treeDepth];
    signal input noteLeafHash;
    signal input spentOutputLeaf;

    // Nullifier tree roots + indexed insert (active when spends)
    signal input preNullifierRoot;
    signal input postNullifierRoot;
    // predecessor leaf before/after
    signal input nfPredType;
    signal input nfPredIndex;
    signal input nfPredKey;
    signal input nfPredSuccIndex;
    signal input nfPredSuccKey;
    signal input nfPredPathElements[treeDepth];
    signal input nfPredPathIndices[treeDepth];
    // new nullifier leaf
    signal input nfNewIndex;
    signal input nfNewSuccIndex;
    signal input nfNewSuccKey;
    // empty-slot path under mid-root (after pred update)
    signal input nfEmptyPathElements[treeDepth];
    signal input nfEmptyPathIndices[treeDepth];

    // Encrypted record (active when creates)
    signal input recordLimbs[8];
    signal input esk;          // ephemeral scalar
    signal input Vx;
    signal input Vy;           // recipient view point
    signal input Ex;
    signal input Ey;           // ephemeral point
    signal input encRho;
    signal input encR;
    signal input encTag;
    // create-side rho/r for deposit (= primary) or transfer create
    signal input encryptRho;
    signal input encryptR;

    // --- public limb binding ---
    publicInput0 === limb0;
    publicInput1 === limb1;

    // --- kind one-hot ---
    signal k1; k1 <== kind - 1;
    signal k2; k2 <== kind - 2;
    signal k3; k3 <== kind - 3;
    component iz1 = IsZero(); iz1.in <== k1;
    component iz2 = IsZero(); iz2.in <== k2;
    component iz3 = IsZero(); iz3.in <== k3;
    iz1.out + iz2.out + iz3.out === 1;
    signal isDeposit; isDeposit <== iz1.out;
    signal isTransfer; isTransfer <== iz2.out;
    signal isWithdraw; isWithdraw <== iz3.out;
    signal spends; spends <== isTransfer + isWithdraw;
    signal creates; creates <== isDeposit + isTransfer;

    // --- counter algebra ---
    postActionSequence === preActionSequence + 1;
    postNoteCount === preNoteCount + creates;
    postNullifierCount === preNullifierCount + spends;
    var D = 10000000;
    denomination === D;
    postReserve === preReserve + isDeposit * D - isWithdraw * D;

    signal preLive;
    preLive <== preNoteCount - preNullifierCount;
    signal liveGap;
    liveGap <== preMaximumLiveNotes - preLive;
    component gapZero = IsZero(); gapZero.in <== liveGap;
    isDeposit * gapZero.out === 0;
    component liveZero = IsZero(); liveZero.in <== preLive;
    isWithdraw * liveZero.out === 0;

    // --- primary note commitment ---
    component noteHash = Poseidon(9);
    noteHash.inputs[0] <== DOMAIN_NOTE();
    noteHash.inputs[1] <== profileIdLo;
    noteHash.inputs[2] <== profileIdHi;
    noteHash.inputs[3] <== instanceIdLo;
    noteHash.inputs[4] <== instanceIdHi;
    noteHash.inputs[5] <== denomination;
    noteHash.inputs[6] <== authority;
    noteHash.inputs[7] <== rho;
    noteHash.inputs[8] <== r;
    cm === noteHash.out;

    // --- transfer create-note commitment ---
    component createNoteHash = Poseidon(9);
    createNoteHash.inputs[0] <== DOMAIN_NOTE();
    createNoteHash.inputs[1] <== profileIdLo;
    createNoteHash.inputs[2] <== profileIdHi;
    createNoteHash.inputs[3] <== instanceIdLo;
    createNoteHash.inputs[4] <== instanceIdHi;
    createNoteHash.inputs[5] <== denomination;
    createNoteHash.inputs[6] <== createAuthority;
    createNoteHash.inputs[7] <== createRho;
    createNoteHash.inputs[8] <== createR;
    signal createCmDiff;
    createCmDiff <== createCm - createNoteHash.out;
    isTransfer * createCmDiff === 0;
    signal createSame;
    createSame <== createCm - cm;
    isDeposit * createSame === 0;
    isWithdraw * createCm === 0;
    isWithdraw * createAuthority === 0;
    isWithdraw * createRho === 0;
    isWithdraw * createR === 0;
    isDeposit * createAuthority === 0;
    isDeposit * createRho === 0;
    isDeposit * createR === 0;

    // --- nullifier ---
    component nfHashFull = Poseidon(8);
    nfHashFull.inputs[0] <== DOMAIN_NULLIFIER();
    nfHashFull.inputs[1] <== profileIdLo;
    nfHashFull.inputs[2] <== profileIdHi;
    nfHashFull.inputs[3] <== instanceIdLo;
    nfHashFull.inputs[4] <== instanceIdHi;
    nfHashFull.inputs[5] <== sk;
    nfHashFull.inputs[6] <== rho;
    nfHashFull.inputs[7] <== cm;
    signal nfDiff;
    nfDiff <== nf - nfHashFull.out;
    spends * nfDiff === 0;
    isDeposit * nf === 0;
    isDeposit * publicNullifier === 0;
    signal pubNfDiff;
    pubNfDiff <== publicNullifier - nf;
    spends * pubNfDiff === 0;

    // --- output leaf ---
    signal leafCm;
    leafCm <== cm + isTransfer * (createCm - cm);
    component leafHash = Poseidon(3);
    leafHash.inputs[0] <== DOMAIN_NOTE_LEAF();
    leafHash.inputs[1] <== leafCm;
    leafHash.inputs[2] <== recordCommitment;
    signal leafDiff;
    leafDiff <== outputNoteLeaf - leafHash.out;
    creates * leafDiff === 0;
    isWithdraw * outputNoteLeaf === 0;

    // --- Note Merkle path (depth treeDepth) ---
    // create: empty slot under pre → filled under post (same siblings)
    // withdraw: membership of spent leaf under pre (== post)
    component emptyNote = Poseidon(2);
    emptyNote.inputs[0] <== DOMAIN_NOTE_EMPTY();
    emptyNote.inputs[1] <== 0;

    component treeLeaf = Poseidon(2);
    treeLeaf.inputs[0] <== DOMAIN_NOTE_LEAF();
    treeLeaf.inputs[1] <== outputNoteLeaf;
    component spendTreeLeaf = Poseidon(2);
    spendTreeLeaf.inputs[0] <== DOMAIN_NOTE_LEAF();
    spendTreeLeaf.inputs[1] <== spentOutputLeaf;

    signal pathLeaf;
    signal leafDelta;
    leafDelta <== spendTreeLeaf.out - treeLeaf.out;
    pathLeaf <== treeLeaf.out + isWithdraw * leafDelta;
    isDeposit * spentOutputLeaf === 0;
    noteLeafHash === pathLeaf;

    // membership / post-root for pathLeaf
    component noteMerkle = MerklePoseidonDomain(treeDepth, DOMAIN_NOTE_NODE());
    noteMerkle.leaf <== noteLeafHash;
    for (var i = 0; i < treeDepth; i++) {
        noteMerkle.pathElements[i] <== notePathElements[i];
        noteMerkle.pathIndices[i] <== notePathIndices[i];
    }
    signal rootDiffPost;
    rootDiffPost <== postNoteRoot - noteMerkle.root;
    creates * rootDiffPost === 0;
    signal rootStay;
    rootStay <== postNoteRoot - preNoteRoot;
    isWithdraw * rootStay === 0;
    signal rootDiffPreW;
    rootDiffPreW <== preNoteRoot - noteMerkle.root;
    isWithdraw * rootDiffPreW === 0;

    // create: empty under pre with same path
    component emptyNoteMerkle = MerklePoseidonDomain(treeDepth, DOMAIN_NOTE_NODE());
    emptyNoteMerkle.leaf <== emptyNote.out;
    for (var i = 0; i < treeDepth; i++) {
        emptyNoteMerkle.pathElements[i] <== notePathElements[i];
        emptyNoteMerkle.pathIndices[i] <== notePathIndices[i];
    }
    signal emptyRootDiff;
    emptyRootDiff <== preNoteRoot - emptyNoteMerkle.root;
    creates * emptyRootDiff === 0;

    // sk zero on deposit; rho/r nonzero when used
    isDeposit * sk === 0;
    component rhoZ = IsZero(); rhoZ.in <== rho;
    component rZ = IsZero(); rZ.in <== r;
    (isDeposit + spends) * rhoZ.out === 0;
    (isDeposit + spends) * rZ.out === 0;
    component cRhoZ = IsZero(); cRhoZ.in <== createRho;
    component cRZ = IsZero(); cRZ.in <== createR;
    isTransfer * cRhoZ.out === 0;
    isTransfer * cRZ.out === 0;

    // ========== Indexed nullifier insert (when spends) ==========
    // Soft-gated: Merkle checks apply only when spends==1 (deposit may use zero dummies).
    component predBeforeHash = Poseidon(6);
    predBeforeHash.inputs[0] <== DOMAIN_NULLIFIER_LEAF();
    predBeforeHash.inputs[1] <== nfPredType;
    predBeforeHash.inputs[2] <== nfPredIndex;
    predBeforeHash.inputs[3] <== nfPredKey;
    predBeforeHash.inputs[4] <== nfPredSuccIndex;
    predBeforeHash.inputs[5] <== nfPredSuccKey;

    component predAfterHash = Poseidon(6);
    predAfterHash.inputs[0] <== DOMAIN_NULLIFIER_LEAF();
    predAfterHash.inputs[1] <== nfPredType;
    predAfterHash.inputs[2] <== nfPredIndex;
    predAfterHash.inputs[3] <== nfPredKey;
    predAfterHash.inputs[4] <== nfNewIndex;
    predAfterHash.inputs[5] <== nf;

    component newNfLeaf = Poseidon(6);
    newNfLeaf.inputs[0] <== DOMAIN_NULLIFIER_LEAF();
    newNfLeaf.inputs[1] <== NF_TYPE_NORMAL();
    newNfLeaf.inputs[2] <== nfNewIndex;
    newNfLeaf.inputs[3] <== nf;
    newNfLeaf.inputs[4] <== nfNewSuccIndex;
    newNfLeaf.inputs[5] <== nfNewSuccKey;

    component emptyNf = Poseidon(2);
    emptyNf.inputs[0] <== DOMAIN_NULLIFIER_EMPTY();
    emptyNf.inputs[1] <== 0;

    // predBefore under preNullifierRoot
    component predOldM = MerklePoseidonDomain(treeDepth, DOMAIN_NULLIFIER_NODE());
    predOldM.leaf <== predBeforeHash.out;
    for (var i = 0; i < treeDepth; i++) {
        predOldM.pathElements[i] <== nfPredPathElements[i];
        predOldM.pathIndices[i] <== nfPredPathIndices[i];
    }
    spends * (predOldM.root - preNullifierRoot) === 0;

    // predAfter → midRoot (same path as pred)
    component predNewM = MerklePoseidonDomain(treeDepth, DOMAIN_NULLIFIER_NODE());
    predNewM.leaf <== predAfterHash.out;
    for (var i = 0; i < treeDepth; i++) {
        predNewM.pathElements[i] <== nfPredPathElements[i];
        predNewM.pathIndices[i] <== nfPredPathIndices[i];
    }

    // empty under midRoot
    component emptyMidM = MerklePoseidonDomain(treeDepth, DOMAIN_NULLIFIER_NODE());
    emptyMidM.leaf <== emptyNf.out;
    for (var i = 0; i < treeDepth; i++) {
        emptyMidM.pathElements[i] <== nfEmptyPathElements[i];
        emptyMidM.pathIndices[i] <== nfEmptyPathIndices[i];
    }
    spends * (emptyMidM.root - predNewM.root) === 0;

    // new leaf under postNullifierRoot
    component newLeafM = MerklePoseidonDomain(treeDepth, DOMAIN_NULLIFIER_NODE());
    newLeafM.leaf <== newNfLeaf.out;
    for (var i = 0; i < treeDepth; i++) {
        newLeafM.pathElements[i] <== nfEmptyPathElements[i];
        newLeafM.pathIndices[i] <== nfEmptyPathIndices[i];
    }
    spends * (newLeafM.root - postNullifierRoot) === 0;

    signal nfRootStay;
    nfRootStay <== postNullifierRoot - preNullifierRoot;
    isDeposit * nfRootStay === 0;

    signal succIdxDiff;
    succIdxDiff <== nfNewSuccIndex - nfPredSuccIndex;
    spends * succIdxDiff === 0;
    signal succKeyDiff;
    succKeyDiff <== nfNewSuccKey - nfPredSuccKey;
    spends * succKeyDiff === 0;

    // ordering over full Fr via 128-bit limb lexicographic compare (safe for all Fr)
    // a < b  iff  a_hi < b_hi  OR  (a_hi == b_hi AND a_lo < b_lo)
    component predIsMin = IsZero();
    predIsMin.in <== nfPredType - NF_TYPE_MIN();

    signal predKeyEff;
    predKeyEff <== nfPredKey * (1 - predIsMin.out);

    component predKeyBits = Num2Bits(254);
    predKeyBits.in <== predKeyEff;
    component nfBitsPred = Num2Bits(254);
    nfBitsPred.in <== nf;
    // reconstruct 127-bit hi/lo (254 = 127+127)
    signal predLo; signal predHi; signal nfLoP; signal nfHiP;
    var lo = 0;
    var hi = 0;
    var nlo = 0;
    var nhi = 0;
    for (var i = 0; i < 127; i++) {
        lo += predKeyBits.out[i] * (2 ** i);
        hi += predKeyBits.out[127 + i] * (2 ** i);
        nlo += nfBitsPred.out[i] * (2 ** i);
        nhi += nfBitsPred.out[127 + i] * (2 ** i);
    }
    predLo <== lo;
    predHi <== hi;
    nfLoP <== nlo;
    nfHiP <== nhi;

    component hiLtP = LessThan(127);
    hiLtP.in[0] <== predHi;
    hiLtP.in[1] <== nfHiP;
    component hiEqP = IsEqual();
    hiEqP.in[0] <== predHi;
    hiEqP.in[1] <== nfHiP;
    component loLtP = LessThan(127);
    loLtP.in[0] <== predLo;
    loLtP.in[1] <== nfLoP;
    signal predLt;
    predLt <== hiLtP.out + hiEqP.out * loLtP.out;
    signal predOrder;
    predOrder <== predLt + predIsMin.out - predLt * predIsMin.out;
    spends * (1 - predOrder) === 0;

    component succIsMaxIdx = IsZero();
    succIsMaxIdx.in <== nfPredSuccIndex - 1;

    component succKeyBits = Num2Bits(254);
    succKeyBits.in <== nfPredSuccKey;
    component nfBitsSucc = Num2Bits(254);
    nfBitsSucc.in <== nf;
    signal succLo; signal succHi; signal nfLoS; signal nfHiS;
    var slo = 0;
    var shi = 0;
    var snlo = 0;
    var snhi = 0;
    for (var i = 0; i < 127; i++) {
        slo += succKeyBits.out[i] * (2 ** i);
        shi += succKeyBits.out[127 + i] * (2 ** i);
        snlo += nfBitsSucc.out[i] * (2 ** i);
        snhi += nfBitsSucc.out[127 + i] * (2 ** i);
    }
    succLo <== slo;
    succHi <== shi;
    nfLoS <== snlo;
    nfHiS <== snhi;
    component hiLtS = LessThan(127);
    hiLtS.in[0] <== nfHiS;
    hiLtS.in[1] <== succHi;
    component hiEqS = IsEqual();
    hiEqS.in[0] <== nfHiS;
    hiEqS.in[1] <== succHi;
    component loLtS = LessThan(127);
    loLtS.in[0] <== nfLoS;
    loLtS.in[1] <== succLo;
    signal succLt;
    succLt <== hiLtS.out + hiEqS.out * loLtS.out;
    signal succOrder;
    succOrder <== succLt + succIsMaxIdx.out - succLt * succIsMaxIdx.out;
    spends * (1 - succOrder) === 0;

    // ========== Record commitment + encryption (when creates) ==========
    component rcSponge = RecordCommitmentSponge();
    for (var i = 0; i < 8; i++) {
        rcSponge.limbs[i] <== recordLimbs[i];
    }
    signal rcDiff;
    rcDiff <== recordCommitment - rcSponge.out;
    creates * rcDiff === 0;
    isWithdraw * recordCommitment === 0;

    // E = [esk] Base8
    component pbk = BabyPbk();
    pbk.in <== esk;
    signal exDiff; exDiff <== Ex - pbk.Ax;
    signal eyDiff; eyDiff <== Ey - pbk.Ay;
    creates * exDiff === 0;
    creates * eyDiff === 0;

    // shared = [esk] V
    component eskBits = Num2Bits(253);
    eskBits.in <== esk;
    component mulV = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) {
        mulV.e[i] <== eskBits.out[i];
    }
    mulV.p[0] <== Vx;
    mulV.p[1] <== Vy;

    // ss = Poseidon(RECORD, shared.x, shared.y)
    component ssH = Poseidon(3);
    ssH.inputs[0] <== DOMAIN_RECORD();
    ssH.inputs[1] <== mulV.out[0];
    ssH.inputs[2] <== mulV.out[1];

    component maskRho = Poseidon(3);
    maskRho.inputs[0] <== DOMAIN_RECORD();
    maskRho.inputs[1] <== ssH.out;
    maskRho.inputs[2] <== 1;

    component maskR = Poseidon(3);
    maskR.inputs[0] <== DOMAIN_RECORD();
    maskR.inputs[1] <== ssH.out;
    maskR.inputs[2] <== 2;

    // encRho === encryptRho + maskRho (mod p is free in field)
    signal encRhoDiff;
    encRhoDiff <== encRho - (encryptRho + maskRho.out);
    creates * encRhoDiff === 0;
    signal encRDiff;
    encRDiff <== encR - (encryptR + maskR.out);
    creates * encRDiff === 0;

    // encrypt cm for tag: deposit→cm, transfer→createCm
    signal encCm;
    encCm <== cm + isTransfer * (createCm - cm);

    // tag = Poseidon(RECORD, ss, profileLo, profileHi, instanceLo, instanceHi, cm, Ex, Ey, encRho, encR)
    // Poseidon arity 11 = domain + 10 fields → Poseidon(11)
    component tagH = Poseidon(11);
    tagH.inputs[0] <== DOMAIN_RECORD();
    tagH.inputs[1] <== ssH.out;
    tagH.inputs[2] <== profileIdLo;
    tagH.inputs[3] <== profileIdHi;
    tagH.inputs[4] <== instanceIdLo;
    tagH.inputs[5] <== instanceIdHi;
    tagH.inputs[6] <== encCm;
    tagH.inputs[7] <== Ex;
    tagH.inputs[8] <== Ey;
    tagH.inputs[9] <== encRho;
    tagH.inputs[10] <== encR;
    signal tagDiff;
    tagDiff <== encTag - tagH.out;
    creates * tagDiff === 0;

    // encryptRho/R binding: deposit uses primary rho/r; transfer uses create*
    signal eRhoDep; eRhoDep <== encryptRho - rho;
    isDeposit * eRhoDep === 0;
    signal eRDep; eRDep <== encryptR - r;
    isDeposit * eRDep === 0;
    signal eRhoTr; eRhoTr <== encryptRho - createRho;
    isTransfer * eRhoTr === 0;
    signal eRTr; eRTr <== encryptR - createR;
    isTransfer * eRTr === 0;

    // BabyJub on-curve checks for V and E
    component vCheck = BabyCheck();
    vCheck.x <== Vx;
    vCheck.y <== Vy;
    component eCheck = BabyCheck();
    eCheck.x <== Ex;
    eCheck.y <== Ey;

    // esk nonzero when creates
    component eskZ = IsZero(); eskZ.in <== esk;
    creates * eskZ.out === 0;
}

// Production tree depth 32 (plan pin). Requires ptau power ≥ 18 for expanded constraints.
component main {public [publicInput0, publicInput1]} = PoolActionV2Direct(32);
