pragma circom 2.0.0;

// G1 feasibility circuit. This is a real constraint system using circomlib
// Poseidon and SHA-256. Its fixed semantic packet layout is documented in
// CIRCUIT_SCOPE.md; it is not a BCH verifier or a production profile.
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/sha256/sha256.circom";

template Bool() {
    signal input in;
    in * (in - 1) === 0;
}

template Select() {
    signal input whenZero;
    signal input whenOne;
    signal input select;
    signal output out;
    out <== whenZero + select * (whenOne - whenZero);
}

template Hash3() {
    signal input tag;
    signal input left;
    signal input right;
    signal output out;
    component p = Poseidon(3);
    p.inputs[0] <== tag;
    p.inputs[1] <== left;
    p.inputs[2] <== right;
    out <== p.out;
}

template StateCommitment() {
    signal input profileHi;
    signal input profileLo;
    signal input instanceHi;
    signal input instanceLo;
    signal input noteRoot;
    signal input nullifierRoot;
    signal input nextLeafIndex;
    signal input actionSequence;
    signal input liveNoteCount;
    signal input reserveSats;
    signal input maximumReserve;
    signal output out;
    component p = Poseidon(12);
    p.inputs[0] <== 1030;
    p.inputs[1] <== profileHi;
    p.inputs[2] <== profileLo;
    p.inputs[3] <== instanceHi;
    p.inputs[4] <== instanceLo;
    p.inputs[5] <== noteRoot;
    p.inputs[6] <== nullifierRoot;
    p.inputs[7] <== nextLeafIndex;
    p.inputs[8] <== actionSequence;
    p.inputs[9] <== liveNoteCount;
    p.inputs[10] <== reserveSats;
    p.inputs[11] <== maximumReserve;
    out <== p.out;
}

template G1Relation() {
    var D = 10000000;
    var NOTE_DEPTH = 32;
    var NULLIFIER_DEPTH = 128;
    var RECORD_BITS = 1536;
    var PACKET_BITS = 5472;
    // Exactly two public Groth16 inputs: BE_u128(SHA256(packet)) halves.
    signal input publicDigestHi;
    signal input publicDigestLo;

    // Action selector: deposit, transfer, withdrawal.
    signal input isDeposit;
    signal input isTransfer;
    signal input isWithdrawal;
    component bDeposit = Bool(); bDeposit.in <== isDeposit;
    component bTransfer = Bool(); bTransfer.in <== isTransfer;
    component bWithdrawal = Bool(); bWithdrawal.in <== isWithdrawal;
    isDeposit + isTransfer + isWithdrawal === 1;
    signal hasSpend <== isTransfer + isWithdrawal;
    signal hasOutput <== isDeposit + isTransfer;

    // Header identities are SHA-256 digest limbs and must be unsigned u128.
    signal input profileHi;
    signal input profileLo;
    signal input instanceHi;
    signal input instanceLo;
    component profileHiBits = Num2Bits(128); profileHiBits.in <== profileHi;
    component profileLoBits = Num2Bits(128); profileLoBits.in <== profileLo;
    component instanceHiBits = Num2Bits(128); instanceHiBits.in <== instanceHi;
    component instanceLoBits = Num2Bits(128); instanceLoBits.in <== instanceLo;

    // State inputs exclude identifiers because the packet header authenticates
    // them once and both state commitments consume the same four limbs.
    signal input preNoteRoot;
    signal input preNullifierRoot;
    signal input preNextLeafIndex;
    signal input preActionSequence;
    signal input preLiveNoteCount;
    signal input preReserveSats;
    signal input preMaximumReserve;
    signal input preStateCommitment;
    signal input postNoteRoot;
    signal input postNullifierRoot;
    signal input postNextLeafIndex;
    signal input postActionSequence;
    signal input postLiveNoteCount;
    signal input postReserveSats;
    signal input postMaximumReserve;
    signal input postStateCommitment;
    signal input maximumLiveNotes;

    component preNoteRootBits = Num2Bits(254); preNoteRootBits.in <== preNoteRoot;
    component preNullifierRootBits = Num2Bits(254); preNullifierRootBits.in <== preNullifierRoot;
    component postNoteRootBits = Num2Bits(254); postNoteRootBits.in <== postNoteRoot;
    component postNullifierRootBits = Num2Bits(254); postNullifierRootBits.in <== postNullifierRoot;
    component preCommitmentBits = Num2Bits(254); preCommitmentBits.in <== preStateCommitment;
    component postCommitmentBits = Num2Bits(254); postCommitmentBits.in <== postStateCommitment;
    component preNextBits = Num2Bits(32); preNextBits.in <== preNextLeafIndex;
    component postNextBits = Num2Bits(32); postNextBits.in <== postNextLeafIndex;
    component preSeqBits = Num2Bits(64); preSeqBits.in <== preActionSequence;
    component postSeqBits = Num2Bits(64); postSeqBits.in <== postActionSequence;
    component preLiveBits = Num2Bits(32); preLiveBits.in <== preLiveNoteCount;
    component postLiveBits = Num2Bits(32); postLiveBits.in <== postLiveNoteCount;
    component preReserveBits = Num2Bits(64); preReserveBits.in <== preReserveSats;
    component postReserveBits = Num2Bits(64); postReserveBits.in <== postReserveSats;
    component preMaxBits = Num2Bits(64); preMaxBits.in <== preMaximumReserve;
    component postMaxBits = Num2Bits(64); postMaxBits.in <== postMaximumReserve;
    component maximumLiveBits = Num2Bits(32); maximumLiveBits.in <== maximumLiveNotes;

    component preState = StateCommitment();
    preState.profileHi <== profileHi; preState.profileLo <== profileLo;
    preState.instanceHi <== instanceHi; preState.instanceLo <== instanceLo;
    preState.noteRoot <== preNoteRoot; preState.nullifierRoot <== preNullifierRoot;
    preState.nextLeafIndex <== preNextLeafIndex; preState.actionSequence <== preActionSequence;
    preState.liveNoteCount <== preLiveNoteCount; preState.reserveSats <== preReserveSats; preState.maximumReserve <== preMaximumReserve;
    preStateCommitment === preState.out;
    component postState = StateCommitment();
    postState.profileHi <== profileHi; postState.profileLo <== profileLo;
    postState.instanceHi <== instanceHi; postState.instanceLo <== instanceLo;
    postState.noteRoot <== postNoteRoot; postState.nullifierRoot <== postNullifierRoot;
    postState.nextLeafIndex <== postNextLeafIndex; postState.actionSequence <== postActionSequence;
    postState.liveNoteCount <== postLiveNoteCount; postState.reserveSats <== postReserveSats; postState.maximumReserve <== postMaximumReserve;
    postStateCommitment === postState.out;

    // State equations and range/cap checks.
    postActionSequence === preActionSequence + 1;
    postNextLeafIndex === preNextLeafIndex + hasOutput;
    postLiveNoteCount === preLiveNoteCount + isDeposit - isWithdrawal;
    preReserveSats === preLiveNoteCount * D;
    postReserveSats === postLiveNoteCount * D;
    postReserveSats === preReserveSats + (isDeposit - isWithdrawal) * D;
    postMaximumReserve === preMaximumReserve;
    preMaximumReserve === maximumLiveNotes * D;
    component preCap = LessEqThan(64); preCap.in[0] <== preReserveSats; preCap.in[1] <== preMaximumReserve; preCap.out === 1;
    component postCap = LessEqThan(64); postCap.in[0] <== postReserveSats; postCap.in[1] <== postMaximumReserve; postCap.out === 1;

    // Input spend authority, commitment, and nullifier. The relations are
    // gated only for deposits; zero inactive input fields are required there.
    signal input inSk;
    signal input inRho;
    signal input inR;
    signal input inputAk;
    signal input inputCm;
    signal input inputNf;
    component inSkBits = Num2Bits(254); inSkBits.in <== inSk;
    component inRhoBits = Num2Bits(254); inRhoBits.in <== inRho;
    component inRBits = Num2Bits(254); inRBits.in <== inR;
    component inputAkBits = Num2Bits(254); inputAkBits.in <== inputAk;
    component inputCmBits = Num2Bits(254); inputCmBits.in <== inputCm;
    component inputNfBits = Num2Bits(254); inputNfBits.in <== inputNf;
    component spendAuth = Poseidon(6);
    spendAuth.inputs[0] <== 1001; spendAuth.inputs[1] <== profileHi; spendAuth.inputs[2] <== profileLo;
    spendAuth.inputs[3] <== instanceHi; spendAuth.inputs[4] <== instanceLo; spendAuth.inputs[5] <== inSk;
    component inputNote = Poseidon(9);
    inputNote.inputs[0] <== 1002; inputNote.inputs[1] <== profileHi; inputNote.inputs[2] <== profileLo;
    inputNote.inputs[3] <== instanceHi; inputNote.inputs[4] <== instanceLo; inputNote.inputs[5] <== D;
    inputNote.inputs[6] <== inputAk; inputNote.inputs[7] <== inRho; inputNote.inputs[8] <== inR;
    component inputNullifier = Poseidon(7);
    inputNullifier.inputs[0] <== 1003; inputNullifier.inputs[1] <== profileHi; inputNullifier.inputs[2] <== profileLo;
    inputNullifier.inputs[3] <== instanceHi; inputNullifier.inputs[4] <== instanceLo; inputNullifier.inputs[5] <== inSk; inputNullifier.inputs[6] <== inRho;
    hasSpend * (inputAk - spendAuth.out) === 0;
    hasSpend * (inputCm - inputNote.out) === 0;
    hasSpend * (inputNf - inputNullifier.out) === 0;
    isDeposit * inputAk === 0; isDeposit * inputCm === 0; isDeposit * inputNf === 0;
    isDeposit * inSk === 0; isDeposit * inRho === 0; isDeposit * inR === 0;
    component inputSkZero = IsZero(); inputSkZero.in <== inSk; hasSpend * inputSkZero.out === 0;
    component inputRhoZero = IsZero(); inputRhoZero.in <== inRho; hasSpend * inputRhoZero.out === 0;
    component inputRZero = IsZero(); inputRZero.in <== inR; hasSpend * inputRZero.out === 0;
    component inputCmZero = IsZero(); inputCmZero.in <== inputCm; hasSpend * inputCmZero.out === 0;
    component inputNfZero = IsZero(); inputNfZero.in <== inputNf; hasSpend * inputNfZero.out === 0;

    // Output note has a recipient-selected ak. Its witness fields are inactive
    // and zero for withdrawal, and its fixed recovery record is zero then too.
    signal input outputAk;
    signal input outputRho;
    signal input outputR;
    signal input outputCm;
    component outputAkBits = Num2Bits(254); outputAkBits.in <== outputAk;
    component outputRhoBits = Num2Bits(254); outputRhoBits.in <== outputRho;
    component outputRBits = Num2Bits(254); outputRBits.in <== outputR;
    component outputCmBits = Num2Bits(254); outputCmBits.in <== outputCm;
    component outputNote = Poseidon(9);
    outputNote.inputs[0] <== 1002; outputNote.inputs[1] <== profileHi; outputNote.inputs[2] <== profileLo;
    outputNote.inputs[3] <== instanceHi; outputNote.inputs[4] <== instanceLo; outputNote.inputs[5] <== D;
    outputNote.inputs[6] <== outputAk; outputNote.inputs[7] <== outputRho; outputNote.inputs[8] <== outputR;
    hasOutput * (outputCm - outputNote.out) === 0;
    isWithdrawal * outputAk === 0; isWithdrawal * outputRho === 0; isWithdrawal * outputR === 0; isWithdrawal * outputCm === 0;
    component outputAkZero = IsZero(); outputAkZero.in <== outputAk; hasOutput * outputAkZero.out === 0;
    component outputRhoZero = IsZero(); outputRhoZero.in <== outputRho; hasOutput * outputRhoZero.out === 0;
    component outputRZero = IsZero(); outputRZero.in <== outputR; hasOutput * outputRZero.out === 0;
    component outputCmZero = IsZero(); outputCmZero.in <== outputCm; hasOutput * outputCmZero.out === 0;

    // Append proof: pre-next leaf is empty and post-next leaf is outputCm.
    signal input appendSiblings[NOTE_DEPTH];
    component noteEmpty = Poseidon(2); noteEmpty.inputs[0] <== 1012; noteEmpty.inputs[1] <== 0;
    component appendEmptyNode[NOTE_DEPTH];
    component appendOutputLeaf = Poseidon(2); appendOutputLeaf.inputs[0] <== 1010; appendOutputLeaf.inputs[1] <== outputCm;
    component appendOutputNode[NOTE_DEPTH];
    signal appendEmptyCurrent[NOTE_DEPTH+1];
    signal appendOutputCurrent[NOTE_DEPTH+1];
    signal appendLeftEmpty[NOTE_DEPTH]; signal appendRightEmpty[NOTE_DEPTH];
    signal appendLeftOutput[NOTE_DEPTH]; signal appendRightOutput[NOTE_DEPTH];
    component appendSelectLeftEmpty[NOTE_DEPTH]; component appendSelectRightEmpty[NOTE_DEPTH];
    component appendSelectLeftOutput[NOTE_DEPTH]; component appendSelectRightOutput[NOTE_DEPTH];
    appendEmptyCurrent[0] <== noteEmpty.out; appendOutputCurrent[0] <== appendOutputLeaf.out;
    for (var i = 0; i < NOTE_DEPTH; i++) {
        appendSelectLeftEmpty[i] = Select(); appendSelectLeftEmpty[i].whenZero <== appendEmptyCurrent[i]; appendSelectLeftEmpty[i].whenOne <== appendSiblings[i]; appendSelectLeftEmpty[i].select <== preNextBits.out[i]; appendLeftEmpty[i] <== appendSelectLeftEmpty[i].out;
        appendSelectRightEmpty[i] = Select(); appendSelectRightEmpty[i].whenZero <== appendSiblings[i]; appendSelectRightEmpty[i].whenOne <== appendEmptyCurrent[i]; appendSelectRightEmpty[i].select <== preNextBits.out[i]; appendRightEmpty[i] <== appendSelectRightEmpty[i].out;
        appendSelectLeftOutput[i] = Select(); appendSelectLeftOutput[i].whenZero <== appendOutputCurrent[i]; appendSelectLeftOutput[i].whenOne <== appendSiblings[i]; appendSelectLeftOutput[i].select <== preNextBits.out[i]; appendLeftOutput[i] <== appendSelectLeftOutput[i].out;
        appendSelectRightOutput[i] = Select(); appendSelectRightOutput[i].whenZero <== appendSiblings[i]; appendSelectRightOutput[i].whenOne <== appendOutputCurrent[i]; appendSelectRightOutput[i].select <== preNextBits.out[i]; appendRightOutput[i] <== appendSelectRightOutput[i].out;
        appendEmptyNode[i] = Hash3(); appendEmptyNode[i].tag <== 1011; appendEmptyNode[i].left <== appendLeftEmpty[i]; appendEmptyNode[i].right <== appendRightEmpty[i];
        appendOutputNode[i] = Hash3(); appendOutputNode[i].tag <== 1011; appendOutputNode[i].left <== appendLeftOutput[i]; appendOutputNode[i].right <== appendRightOutput[i];
        appendEmptyCurrent[i+1] <== appendEmptyNode[i].out; appendOutputCurrent[i+1] <== appendOutputNode[i].out;
    }
    hasOutput * (preNoteRoot - appendEmptyCurrent[NOTE_DEPTH]) === 0;
    hasOutput * (postNoteRoot - appendOutputCurrent[NOTE_DEPTH]) === 0;
    isWithdrawal * (postNoteRoot - preNoteRoot) === 0;
    for (var inactiveAppend = 0; inactiveAppend < NOTE_DEPTH; inactiveAppend++) { isWithdrawal * appendSiblings[inactiveAppend] === 0; }

    // Input membership and collision-fail-closed 128-bit sparse nullifier insertion.
    signal input noteSiblings[NOTE_DEPTH];
    signal input noteIndex;
    component noteIndexBits = Num2Bits(32); noteIndexBits.in <== noteIndex;
    component inputLeaf = Poseidon(2); inputLeaf.inputs[0] <== 1010; inputLeaf.inputs[1] <== inputCm;
    component membershipNode[NOTE_DEPTH]; signal membershipCurrent[NOTE_DEPTH+1]; membershipCurrent[0] <== inputLeaf.out;
    signal memberLeft[NOTE_DEPTH]; signal memberRight[NOTE_DEPTH];
    component memberSelectLeft[NOTE_DEPTH]; component memberSelectRight[NOTE_DEPTH];
    for (var j = 0; j < NOTE_DEPTH; j++) {
        memberSelectLeft[j] = Select(); memberSelectLeft[j].whenZero <== membershipCurrent[j]; memberSelectLeft[j].whenOne <== noteSiblings[j]; memberSelectLeft[j].select <== noteIndexBits.out[j]; memberLeft[j] <== memberSelectLeft[j].out;
        memberSelectRight[j] = Select(); memberSelectRight[j].whenZero <== noteSiblings[j]; memberSelectRight[j].whenOne <== membershipCurrent[j]; memberSelectRight[j].select <== noteIndexBits.out[j]; memberRight[j] <== memberSelectRight[j].out;
        membershipNode[j] = Hash3(); membershipNode[j].tag <== 1011; membershipNode[j].left <== memberLeft[j]; membershipNode[j].right <== memberRight[j];
        membershipCurrent[j+1] <== membershipNode[j].out;
    }
    hasSpend * (preNoteRoot - membershipCurrent[NOTE_DEPTH]) === 0;
    isDeposit * noteIndex === 0;
    for (var inactiveNotePath = 0; inactiveNotePath < NOTE_DEPTH; inactiveNotePath++) { isDeposit * noteSiblings[inactiveNotePath] === 0; }

    signal input nullifierSiblings[NULLIFIER_DEPTH];
    component nullifierEmpty = Poseidon(2); nullifierEmpty.inputs[0] <== 1022; nullifierEmpty.inputs[1] <== 0;
    component nullifierLeaf = Poseidon(2); nullifierLeaf.inputs[0] <== 1020; nullifierLeaf.inputs[1] <== inputNf;
    component nullifierEmptyNode[NULLIFIER_DEPTH]; component nullifierInsertNode[NULLIFIER_DEPTH];
    signal nullifierEmptyCurrent[NULLIFIER_DEPTH+1]; signal nullifierInsertCurrent[NULLIFIER_DEPTH+1];
    signal nullLeftEmpty[NULLIFIER_DEPTH]; signal nullRightEmpty[NULLIFIER_DEPTH];
    signal nullLeftInsert[NULLIFIER_DEPTH]; signal nullRightInsert[NULLIFIER_DEPTH];
    component nullSelectLeftEmpty[NULLIFIER_DEPTH]; component nullSelectRightEmpty[NULLIFIER_DEPTH];
    component nullSelectLeftInsert[NULLIFIER_DEPTH]; component nullSelectRightInsert[NULLIFIER_DEPTH];
    nullifierEmptyCurrent[0] <== nullifierEmpty.out; nullifierInsertCurrent[0] <== nullifierLeaf.out;
    signal nullifierKeyBits[NULLIFIER_DEPTH];
    for (var key = 0; key < 126; key++) { nullifierKeyBits[key] <== inputNfBits.out[128 + key]; }
    nullifierKeyBits[126] <== 0; nullifierKeyBits[127] <== 0;
    for (var k = 0; k < NULLIFIER_DEPTH; k++) {
        // bytes[0..16] as BE u128, traversed least-significant bit first:
        // Num2Bits(254)[128..253], followed by the two canonical zero MSBs.
        nullSelectLeftEmpty[k] = Select(); nullSelectLeftEmpty[k].whenZero <== nullifierEmptyCurrent[k]; nullSelectLeftEmpty[k].whenOne <== nullifierSiblings[k]; nullSelectLeftEmpty[k].select <== nullifierKeyBits[k]; nullLeftEmpty[k] <== nullSelectLeftEmpty[k].out;
        nullSelectRightEmpty[k] = Select(); nullSelectRightEmpty[k].whenZero <== nullifierSiblings[k]; nullSelectRightEmpty[k].whenOne <== nullifierEmptyCurrent[k]; nullSelectRightEmpty[k].select <== nullifierKeyBits[k]; nullRightEmpty[k] <== nullSelectRightEmpty[k].out;
        nullSelectLeftInsert[k] = Select(); nullSelectLeftInsert[k].whenZero <== nullifierInsertCurrent[k]; nullSelectLeftInsert[k].whenOne <== nullifierSiblings[k]; nullSelectLeftInsert[k].select <== nullifierKeyBits[k]; nullLeftInsert[k] <== nullSelectLeftInsert[k].out;
        nullSelectRightInsert[k] = Select(); nullSelectRightInsert[k].whenZero <== nullifierSiblings[k]; nullSelectRightInsert[k].whenOne <== nullifierInsertCurrent[k]; nullSelectRightInsert[k].select <== nullifierKeyBits[k]; nullRightInsert[k] <== nullSelectRightInsert[k].out;
        nullifierEmptyNode[k] = Hash3(); nullifierEmptyNode[k].tag <== 1021; nullifierEmptyNode[k].left <== nullLeftEmpty[k]; nullifierEmptyNode[k].right <== nullRightEmpty[k];
        nullifierInsertNode[k] = Hash3(); nullifierInsertNode[k].tag <== 1021; nullifierInsertNode[k].left <== nullLeftInsert[k]; nullifierInsertNode[k].right <== nullRightInsert[k];
        nullifierEmptyCurrent[k+1] <== nullifierEmptyNode[k].out; nullifierInsertCurrent[k+1] <== nullifierInsertNode[k].out;
    }
    hasSpend * (preNullifierRoot - nullifierEmptyCurrent[NULLIFIER_DEPTH]) === 0;
    hasSpend * (postNullifierRoot - nullifierInsertCurrent[NULLIFIER_DEPTH]) === 0;
    isDeposit * (postNullifierRoot - preNullifierRoot) === 0;
    for (var inactiveNullifierPath = 0; inactiveNullifierPath < NULLIFIER_DEPTH; inactiveNullifierPath++) { isDeposit * nullifierSiblings[inactiveNullifierPath] === 0; }

    // Boundary descriptor and exact fixed record binding.
    signal input boundaryAmount;
    signal input withdrawalScriptHi;
    signal input withdrawalScriptLo;
    component boundaryBits = Num2Bits(64); boundaryBits.in <== boundaryAmount;
    component withdrawalScriptHiBits = Num2Bits(128); withdrawalScriptHiBits.in <== withdrawalScriptHi;
    component withdrawalScriptLoBits = Num2Bits(128); withdrawalScriptLoBits.in <== withdrawalScriptLo;
    boundaryAmount === (isDeposit + isWithdrawal) * D;
    isDeposit * withdrawalScriptHi === 0; isDeposit * withdrawalScriptLo === 0;
    isTransfer * withdrawalScriptHi === 0; isTransfer * withdrawalScriptLo === 0;
    signal input recordBits[RECORD_BITS];
    component recordBoolean[RECORD_BITS];
    for (var r = 0; r < RECORD_BITS; r++) { recordBoolean[r] = Bool(); recordBoolean[r].in <== recordBits[r]; isWithdrawal * recordBits[r] === 0; }

    signal input transactionContextHi;
    signal input transactionContextLo;
    component contextHiBits = Num2Bits(128); contextHiBits.in <== transactionContextHi;
    component contextLoBits = Num2Bits(128); contextLoBits.in <== transactionContextLo;

    // The SHA preimage is a fixed 684-byte typed-prefix packet. Every emitted
    // bit below is constrained from a typed relation signal; there is no caller
    // packet-bit input. CIRCUIT_SCOPE.md lists un-emitted semantic fields.
    signal packet[PACKET_BITS];
    var o = 0;
    // version 1, Chipnet network 2, action code, and six reserved zero bits.
    packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 1; o++;
    packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 1; o++; packet[o] <== 0; o++;
    packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== 0; o++; packet[o] <== isTransfer + isWithdrawal; o++; packet[o] <== isDeposit + isWithdrawal; o++;
    for (var z = 0; z < 8; z++) { packet[o] <== 0; o++; }
    for (var a = 127; a >= 0; a--) { packet[o] <== profileHiBits.out[a]; o++; }
    for (var b = 127; b >= 0; b--) { packet[o] <== profileLoBits.out[b]; o++; }
    for (var c = 127; c >= 0; c--) { packet[o] <== instanceHiBits.out[c]; o++; }
    for (var d = 127; d >= 0; d--) { packet[o] <== instanceLoBits.out[d]; o++; }
    // Pre/post state: Frs encode as 2 leading zero bits plus 254 BE bits.
    for (var q = 0; q < 2; q++) { packet[o] <== 0; o++; } for (var e = 253; e >= 0; e--) { packet[o] <== preNoteRootBits.out[e]; o++; }
    for (var q1 = 0; q1 < 2; q1++) { packet[o] <== 0; o++; } for (var f = 253; f >= 0; f--) { packet[o] <== preNullifierRootBits.out[f]; o++; }
    for (var g = 31; g >= 0; g--) { packet[o] <== preNextBits.out[g]; o++; } for (var h = 63; h >= 0; h--) { packet[o] <== preSeqBits.out[h]; o++; }
    for (var ii = 31; ii >= 0; ii--) { packet[o] <== preLiveBits.out[ii]; o++; } for (var j1 = 63; j1 >= 0; j1--) { packet[o] <== preReserveBits.out[j1]; o++; }
    for (var k1 = 63; k1 >= 0; k1--) { packet[o] <== preMaxBits.out[k1]; o++; }
    // Remaining packet slots are intentionally not emitted in this first compiling subset.
    // A compile-time guard makes the actual SHA message a fixed 684-byte prefix.
    while (o < PACKET_BITS) { packet[o] <== 0; o++; }
    component sha = Sha256(PACKET_BITS);
    for (var s = 0; s < PACKET_BITS; s++) { sha.in[s] <== packet[s]; }
    component digestHi = Bits2Num(128); component digestLo = Bits2Num(128);
    for (var t = 0; t < 128; t++) { digestHi.in[t] <== sha.out[127-t]; digestLo.in[t] <== sha.out[255-t]; }
    publicDigestHi === digestHi.out; publicDigestLo === digestLo.out;
}

component main {public [publicDigestHi, publicDigestLo]} = G1Relation();
