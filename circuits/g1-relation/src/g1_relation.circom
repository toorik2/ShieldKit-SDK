pragma circom 2.0.0;

// G1 feasibility circuit. This is a real constraint system using circomlib
// Poseidon and SHA-256. Its fixed semantic packet layout is documented in
// CIRCUIT_SCOPE.md; it is not a BCH verifier or a production profile.
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/pointbits.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";

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

// The record stores standard circomlib compressed BabyJubJub points as LE
// bytes. recordBits remains BE per byte for the SHA packet, hence this adapter.
template RecordPoint() {
    signal input bits[256];
    signal output point[2];
    component decode = Bits2Point_Strict();
    for (var i = 0; i < 256; i++) decode.in[i] <== bits[i];
    point[0] <== decode.out[0]; point[1] <== decode.out[1];
}

// Reject low-order and identity address keys. EscalarMulAny computes [l]P;
// it is used as an explicit subgroup check, not as an assumption about P.
template PrimeSubgroupPoint() {
    signal input point[2];
    var L = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    component nonidentity = IsZero(); nonidentity.in <== point[0]; nonidentity.out === 0;
    component order = EscalarMulAny(251);
    for (var i = 0; i < 251; i++) order.e[i] <== (L >> i) & 1;
    order.p[0] <== point[0]; order.p[1] <== point[1];
    order.out[0] === 0; order.out[1] === 1;
}

template RecordField(offset) {
    signal input record[1536];
    signal output out;
    record[offset] === 0; record[offset+1] === 0;
    component bits = Bits2Num(254);
    for (var i = 0; i < 254; i++) bits.in[i] <== record[offset + 255 - i];
    // Bits2Num is evaluated in Fr, so zeroing the top two encoded bits alone
    // would still admit a 254-bit integer q >= Fr_MODULUS as q mod Fr. The
    // record is a serialized canonical Fr value, not an arbitrary field
    // representative; retain the raw bits in circomlib's canonical alias gate.
    component canonical = AliasCheck();
    for (var j = 0; j < 254; j++) canonical.in[j] <== bits.in[j];
    out <== bits.out;
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
    var PACKET_BITS = 6016;
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
    component maximumLiveZero = IsZero(); maximumLiveZero.in <== maximumLiveNotes; maximumLiveZero.out === 0;
    component preCap = LessEqThan(64); preCap.in[0] <== preReserveSats; preCap.in[1] <== preMaximumReserve; preCap.out === 1;
    component postCap = LessEqThan(64); postCap.in[0] <== postReserveSats; postCap.in[1] <== postMaximumReserve; postCap.out === 1;
    component maximumBound = LessEqThan(64); maximumBound.in[0] <== preMaximumReserve; maximumBound.in[1] <== 2100000000000000; maximumBound.out === 1;
    // u32 cannot encode 2^32. An output action may append through index
    // 2^32-2 only, leaving postNext <= 2^32-1 representable and rejecting a
    // further append rather than wrapping or claiming an unencodable terminal.
    component appendCapacity = LessEqThan(32); appendCapacity.in[0] <== preNextLeafIndex; appendCapacity.in[1] <== 4294967294;
    hasOutput * (appendCapacity.out - 1) === 0;

    // Input spend authority, commitment, and nullifier. The relations are
    // gated only for deposits; zero inactive input fields are required there.
    signal input inSk;
    signal input inRho;
    signal input inR;
    signal input inputAk;
    signal input inputCm;
    signal input inputNf;
    signal input inputViewX;
    signal input inputViewY;
    component inSkBits = Num2Bits(254); inSkBits.in <== inSk;
    // BabyPbk reduces the scalar modulo the BabyJubJub prime subgroup order.
    // The nullifier hashes the scalar itself, so accepting s + L here would
    // give one note two distinct nullifiers. Require the unique nonzero
    // representative in [1, L-1]. L has 251 bits, within LessThan's limit.
    component inSkCanonical = LessThan(251);
    inSkCanonical.in[0] <== inSk;
    inSkCanonical.in[1] <== 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    inSkCanonical.out === 1;
    component inRhoBits = Num2Bits(254); inRhoBits.in <== inRho;
    component inRBits = Num2Bits(254); inRBits.in <== inR;
    component inputAkBits = Num2Bits(254); inputAkBits.in <== inputAk;
    component inputCmBits = Num2Bits(254); inputCmBits.in <== inputCm;
    component inputNfBits = Num2Bits(254); inputNfBits.in <== inputNf;
    component inputDummyPoint = BabyPbk(); inputDummyPoint.in <== 1;
    isDeposit * inputViewX === 0; isDeposit * inputViewY === 0;
    signal inputViewCoordinates[2];
    component selectInputViewX = Select(); selectInputViewX.whenZero <== inputDummyPoint.Ax; selectInputViewX.whenOne <== inputViewX; selectInputViewX.select <== hasSpend; inputViewCoordinates[0] <== selectInputViewX.out;
    component selectInputViewY = Select(); selectInputViewY.whenZero <== inputDummyPoint.Ay; selectInputViewY.whenOne <== inputViewY; selectInputViewY.select <== hasSpend; inputViewCoordinates[1] <== selectInputViewY.out;
    component inputViewOnCurve = BabyCheck(); inputViewOnCurve.x <== inputViewCoordinates[0]; inputViewOnCurve.y <== inputViewCoordinates[1];
    component inputViewSubgroup = PrimeSubgroupPoint(); inputViewSubgroup.point[0] <== inputViewCoordinates[0]; inputViewSubgroup.point[1] <== inputViewCoordinates[1];
    component spendPublic = BabyPbk(); spendPublic.in <== inSk;
    component spendAuth = Poseidon(9);
    spendAuth.inputs[0] <== 1004; spendAuth.inputs[1] <== profileHi; spendAuth.inputs[2] <== profileLo;
    spendAuth.inputs[3] <== instanceHi; spendAuth.inputs[4] <== instanceLo; spendAuth.inputs[5] <== spendPublic.Ax; spendAuth.inputs[6] <== spendPublic.Ay;
    spendAuth.inputs[7] <== inputViewCoordinates[0]; spendAuth.inputs[8] <== inputViewCoordinates[1];
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
    for (var key = 0; key < NULLIFIER_DEPTH; key++) { nullifierKeyBits[key] <== inputNfBits.out[key]; }
    for (var k = 0; k < NULLIFIER_DEPTH; k++) {
        // bytes[16..32] as BE u128, traversed least-significant bit first:
        // Num2Bits(254)[0..127]. Using the low half avoids the two structurally
        // zero most-significant bits of canonical BN254 Fr encodings.
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

    // Recovery record v2 (192 bytes): version=2, slot=0, compressed ephemeral
    // BabyJubJub point, c_rho, c_r, Poseidon authenticator, and sixty-two zero
    // bytes. The stable recipient point is private witness material: publishing
    // it would link every receipt to a per-instance wallet address.
    hasOutput * recordBits[0] === 0; hasOutput * recordBits[1] === 0; hasOutput * recordBits[2] === 0;
    hasOutput * recordBits[3] === 0; hasOutput * recordBits[4] === 0; hasOutput * recordBits[5] === 0;
    hasOutput * (recordBits[6] - 1) === 0; hasOutput * recordBits[7] === 0;
    for (var recordSlotBit = 8; recordSlotBit < 16; recordSlotBit++) hasOutput * recordBits[recordSlotBit] === 0;
    for (var recordPaddingBit = 1040; recordPaddingBit < 1536; recordPaddingBit++) hasOutput * recordBits[recordPaddingBit] === 0;

    // The zero withdrawal record cannot be decoded as a point. Feed the fixed
    // Base8 point to all always-present gadgets on that inactive branch.
    component dummyPoint = BabyPbk(); dummyPoint.in <== 1;
    component dummyPacked = Point2Bits_Strict(); dummyPacked.in[0] <== dummyPoint.Ax; dummyPacked.in[1] <== dummyPoint.Ay;
    signal input recoverySpendX;
    signal input recoverySpendY;
    signal input recoveryViewX;
    signal input recoveryViewY;
    isWithdrawal * recoverySpendX === 0; isWithdrawal * recoverySpendY === 0;
    isWithdrawal * recoveryViewX === 0; isWithdrawal * recoveryViewY === 0;
    signal spendCoordinates[2]; signal viewCoordinates[2];
    component selectSpendX = Select(); selectSpendX.whenZero <== dummyPoint.Ax; selectSpendX.whenOne <== recoverySpendX; selectSpendX.select <== hasOutput; spendCoordinates[0] <== selectSpendX.out;
    component selectSpendY = Select(); selectSpendY.whenZero <== dummyPoint.Ay; selectSpendY.whenOne <== recoverySpendY; selectSpendY.select <== hasOutput; spendCoordinates[1] <== selectSpendY.out;
    component selectViewX = Select(); selectViewX.whenZero <== dummyPoint.Ax; selectViewX.whenOne <== recoveryViewX; selectViewX.select <== hasOutput; viewCoordinates[0] <== selectViewX.out;
    component selectViewY = Select(); selectViewY.whenZero <== dummyPoint.Ay; selectViewY.whenOne <== recoveryViewY; selectViewY.select <== hasOutput; viewCoordinates[1] <== selectViewY.out;
    component spendOnCurve = BabyCheck(); spendOnCurve.x <== spendCoordinates[0]; spendOnCurve.y <== spendCoordinates[1];
    component spendSubgroup = PrimeSubgroupPoint(); spendSubgroup.point[0] <== spendCoordinates[0]; spendSubgroup.point[1] <== spendCoordinates[1];
    component viewOnCurve = BabyCheck(); viewOnCurve.x <== viewCoordinates[0]; viewOnCurve.y <== viewCoordinates[1];
    component viewSubgroup = PrimeSubgroupPoint(); viewSubgroup.point[0] <== viewCoordinates[0]; viewSubgroup.point[1] <== viewCoordinates[1];
    signal ephemeralCompressed[256];
    component selectEphemeralRecord[256];
    for (var pointBit = 0; pointBit < 256; pointBit++) {
        selectEphemeralRecord[pointBit] = Select(); selectEphemeralRecord[pointBit].whenZero <== dummyPacked.out[pointBit]; selectEphemeralRecord[pointBit].whenOne <== recordBits[16 + 8*(pointBit\8) + 7 - (pointBit%8)]; selectEphemeralRecord[pointBit].select <== hasOutput; ephemeralCompressed[pointBit] <== selectEphemeralRecord[pointBit].out;
    }
    component ephemeralPoint = RecordPoint();
    for (var decodedBit = 0; decodedBit < 256; decodedBit++) ephemeralPoint.bits[decodedBit] <== ephemeralCompressed[decodedBit];
    component ephemeralSubgroup = PrimeSubgroupPoint(); ephemeralSubgroup.point[0] <== ephemeralPoint.point[0]; ephemeralSubgroup.point[1] <== ephemeralPoint.point[1];

    signal input recoveryEphemeralScalar;
    component recoveryEphemeralBits = Num2Bits(253); recoveryEphemeralBits.in <== recoveryEphemeralScalar;
    // As above, make the point witness unique. This is also required for the
    // portable constructor/circuit agreement: portable recovery samples [1,L).
    component recoveryEphemeralCanonical = LessThan(251);
    recoveryEphemeralCanonical.in[0] <== recoveryEphemeralScalar;
    recoveryEphemeralCanonical.in[1] <== 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    recoveryEphemeralCanonical.out === 1;
    isWithdrawal * recoveryEphemeralScalar === 0;
    component recoveryEphemeralZero = IsZero(); recoveryEphemeralZero.in <== recoveryEphemeralScalar; hasOutput * recoveryEphemeralZero.out === 0;
    signal effectiveEphemeralScalar <== recoveryEphemeralScalar + isWithdrawal;
    component effectiveEphemeralBits = Num2Bits(253); effectiveEphemeralBits.in <== effectiveEphemeralScalar;
    component derivedEphemeral = BabyPbk(); derivedEphemeral.in <== effectiveEphemeralScalar;
    derivedEphemeral.Ax === ephemeralPoint.point[0]; derivedEphemeral.Ay === ephemeralPoint.point[1];
    component sharedPoint = EscalarMulAny(253);
    for (var sharedBit = 0; sharedBit < 253; sharedBit++) sharedPoint.e[sharedBit] <== effectiveEphemeralBits.out[sharedBit];
    sharedPoint.p[0] <== viewCoordinates[0]; sharedPoint.p[1] <== viewCoordinates[1];

    component recordRho = RecordField(272); component recordR = RecordField(528); component recordAuth = RecordField(784);
    for (var recordFieldBit = 0; recordFieldBit < 1536; recordFieldBit++) { recordRho.record[recordFieldBit] <== recordBits[recordFieldBit]; recordR.record[recordFieldBit] <== recordBits[recordFieldBit]; recordAuth.record[recordFieldBit] <== recordBits[recordFieldBit]; }
    component recipientAuthority = Poseidon(9);
    recipientAuthority.inputs[0] <== 1004; recipientAuthority.inputs[1] <== profileHi; recipientAuthority.inputs[2] <== profileLo;
    recipientAuthority.inputs[3] <== instanceHi; recipientAuthority.inputs[4] <== instanceLo; recipientAuthority.inputs[5] <== spendCoordinates[0]; recipientAuthority.inputs[6] <== spendCoordinates[1];
    recipientAuthority.inputs[7] <== viewCoordinates[0]; recipientAuthority.inputs[8] <== viewCoordinates[1];
    hasOutput * (outputAk - recipientAuthority.out) === 0;
    component recoveryShared = Poseidon(9);
    recoveryShared.inputs[0] <== 1101; recoveryShared.inputs[1] <== viewCoordinates[0]; recoveryShared.inputs[2] <== viewCoordinates[1]; recoveryShared.inputs[3] <== ephemeralPoint.point[0]; recoveryShared.inputs[4] <== ephemeralPoint.point[1]; recoveryShared.inputs[5] <== sharedPoint.out[0]; recoveryShared.inputs[6] <== sharedPoint.out[1]; recoveryShared.inputs[7] <== outputCm; recoveryShared.inputs[8] <== isDeposit + 2*isTransfer + 3*isWithdrawal;
    component recoveryRhoMask = Poseidon(6); recoveryRhoMask.inputs[0] <== 1102; recoveryRhoMask.inputs[1] <== recoveryShared.out; recoveryRhoMask.inputs[2] <== profileHi; recoveryRhoMask.inputs[3] <== profileLo; recoveryRhoMask.inputs[4] <== instanceHi; recoveryRhoMask.inputs[5] <== instanceLo;
    component recoveryRMask = Poseidon(6); recoveryRMask.inputs[0] <== 1103; recoveryRMask.inputs[1] <== recoveryShared.out; recoveryRMask.inputs[2] <== profileHi; recoveryRMask.inputs[3] <== profileLo; recoveryRMask.inputs[4] <== instanceHi; recoveryRMask.inputs[5] <== instanceLo;
    component recoveryAuthenticator = Poseidon(9);
    recoveryAuthenticator.inputs[0] <== 1104; recoveryAuthenticator.inputs[1] <== recoveryShared.out; recoveryAuthenticator.inputs[2] <== recordRho.out; recoveryAuthenticator.inputs[3] <== recordR.out; recoveryAuthenticator.inputs[4] <== outputAk; recoveryAuthenticator.inputs[5] <== profileHi; recoveryAuthenticator.inputs[6] <== profileLo; recoveryAuthenticator.inputs[7] <== instanceHi; recoveryAuthenticator.inputs[8] <== instanceLo;
    hasOutput * (recordRho.out - outputRho - recoveryRhoMask.out) === 0;
    hasOutput * (recordR.out - outputR - recoveryRMask.out) === 0;
    hasOutput * (recordAuth.out - recoveryAuthenticator.out) === 0;

    signal input transactionContextHi;
    signal input transactionContextLo;
    component contextHiBits = Num2Bits(128); contextHiBits.in <== transactionContextHi;
    component contextLoBits = Num2Bits(128); contextLoBits.in <== transactionContextLo;

    // Exact packages/core serializeActionPacket layout: 752 bytes. Every bit
    // is driven by a typed relation signal; no caller packet-bit input exists.
    signal packet[PACKET_BITS];
    var o = 0;
    var scar[4] = [83, 67, 65, 82];
    for (var headerByte = 0; headerByte < 4; headerByte++) {
        for (var headerBit = 7; headerBit >= 0; headerBit--) { packet[o] <== (scar[headerByte] >> headerBit) & 1; o++; }
    }
    // version=1, network=2, action kind 1/2/3, reserved=0.
    for (var versionBit = 7; versionBit >= 0; versionBit--) { packet[o] <== (1 >> versionBit) & 1; o++; }
    for (var networkBit = 7; networkBit >= 0; networkBit--) { packet[o] <== (2 >> networkBit) & 1; o++; }
    for (var actionBit = 7; actionBit >= 0; actionBit--) {
        if (actionBit == 1) packet[o] <== isTransfer + isWithdrawal;
        else if (actionBit == 0) packet[o] <== isDeposit + isWithdrawal;
        else packet[o] <== 0;
        o++;
    }
    for (var reservedBit = 0; reservedBit < 8; reservedBit++) { packet[o] <== 0; o++; }

    // serializeState(pre): profile, instance, roots, LE counters, commitment.
    for (var preProfileHi = 127; preProfileHi >= 0; preProfileHi--) { packet[o] <== profileHiBits.out[preProfileHi]; o++; }
    for (var preProfileLo = 127; preProfileLo >= 0; preProfileLo--) { packet[o] <== profileLoBits.out[preProfileLo]; o++; }
    for (var preInstanceHi = 127; preInstanceHi >= 0; preInstanceHi--) { packet[o] <== instanceHiBits.out[preInstanceHi]; o++; }
    for (var preInstanceLo = 127; preInstanceLo >= 0; preInstanceLo--) { packet[o] <== instanceLoBits.out[preInstanceLo]; o++; }
    for (var preRootPad = 0; preRootPad < 2; preRootPad++) { packet[o] <== 0; o++; }
    for (var preRootBit = 253; preRootBit >= 0; preRootBit--) { packet[o] <== preNoteRootBits.out[preRootBit]; o++; }
    for (var preNullPad = 0; preNullPad < 2; preNullPad++) { packet[o] <== 0; o++; }
    for (var preNullBit = 253; preNullBit >= 0; preNullBit--) { packet[o] <== preNullifierRootBits.out[preNullBit]; o++; }
    for (var preNextByte = 0; preNextByte < 4; preNextByte++) { for (var preNextBit = 7; preNextBit >= 0; preNextBit--) { packet[o] <== preNextBits.out[8*preNextByte + preNextBit]; o++; } }
    for (var preSeqByte = 0; preSeqByte < 8; preSeqByte++) { for (var preSeqBit = 7; preSeqBit >= 0; preSeqBit--) { packet[o] <== preSeqBits.out[8*preSeqByte + preSeqBit]; o++; } }
    for (var preLiveByte = 0; preLiveByte < 4; preLiveByte++) { for (var preLiveBit = 7; preLiveBit >= 0; preLiveBit--) { packet[o] <== preLiveBits.out[8*preLiveByte + preLiveBit]; o++; } }
    for (var preReserveByte = 0; preReserveByte < 8; preReserveByte++) { for (var preReserveBit = 7; preReserveBit >= 0; preReserveBit--) { packet[o] <== preReserveBits.out[8*preReserveByte + preReserveBit]; o++; } }
    for (var preMaxByte = 0; preMaxByte < 8; preMaxByte++) { for (var preMaxBit = 7; preMaxBit >= 0; preMaxBit--) { packet[o] <== preMaxBits.out[8*preMaxByte + preMaxBit]; o++; } }
    for (var preCommitPad = 0; preCommitPad < 2; preCommitPad++) { packet[o] <== 0; o++; }
    for (var preCommitBit = 253; preCommitBit >= 0; preCommitBit--) { packet[o] <== preCommitmentBits.out[preCommitBit]; o++; }

    // serializeState(post), byte-for-byte identical ordering.
    for (var postProfileHi = 127; postProfileHi >= 0; postProfileHi--) { packet[o] <== profileHiBits.out[postProfileHi]; o++; }
    for (var postProfileLo = 127; postProfileLo >= 0; postProfileLo--) { packet[o] <== profileLoBits.out[postProfileLo]; o++; }
    for (var postInstanceHi = 127; postInstanceHi >= 0; postInstanceHi--) { packet[o] <== instanceHiBits.out[postInstanceHi]; o++; }
    for (var postInstanceLo = 127; postInstanceLo >= 0; postInstanceLo--) { packet[o] <== instanceLoBits.out[postInstanceLo]; o++; }
    for (var postRootPad = 0; postRootPad < 2; postRootPad++) { packet[o] <== 0; o++; }
    for (var postRootBit = 253; postRootBit >= 0; postRootBit--) { packet[o] <== postNoteRootBits.out[postRootBit]; o++; }
    for (var postNullPad = 0; postNullPad < 2; postNullPad++) { packet[o] <== 0; o++; }
    for (var postNullBit = 253; postNullBit >= 0; postNullBit--) { packet[o] <== postNullifierRootBits.out[postNullBit]; o++; }
    for (var postNextByte = 0; postNextByte < 4; postNextByte++) { for (var postNextBit = 7; postNextBit >= 0; postNextBit--) { packet[o] <== postNextBits.out[8*postNextByte + postNextBit]; o++; } }
    for (var postSeqByte = 0; postSeqByte < 8; postSeqByte++) { for (var postSeqBit = 7; postSeqBit >= 0; postSeqBit--) { packet[o] <== postSeqBits.out[8*postSeqByte + postSeqBit]; o++; } }
    for (var postLiveByte = 0; postLiveByte < 4; postLiveByte++) { for (var postLiveBit = 7; postLiveBit >= 0; postLiveBit--) { packet[o] <== postLiveBits.out[8*postLiveByte + postLiveBit]; o++; } }
    for (var postReserveByte = 0; postReserveByte < 8; postReserveByte++) { for (var postReserveBit = 7; postReserveBit >= 0; postReserveBit--) { packet[o] <== postReserveBits.out[8*postReserveByte + postReserveBit]; o++; } }
    for (var postMaxByte = 0; postMaxByte < 8; postMaxByte++) { for (var postMaxBit = 7; postMaxBit >= 0; postMaxBit--) { packet[o] <== postMaxBits.out[8*postMaxByte + postMaxBit]; o++; } }
    for (var postCommitPad = 0; postCommitPad < 2; postCommitPad++) { packet[o] <== 0; o++; }
    for (var postCommitBit = 253; postCommitBit >= 0; postCommitBit--) { packet[o] <== postCommitmentBits.out[postCommitBit]; o++; }

    for (var inputCmPad = 0; inputCmPad < 2; inputCmPad++) { packet[o] <== 0; o++; }
    for (var inputCmBit = 253; inputCmBit >= 0; inputCmBit--) { packet[o] <== inputCmBits.out[inputCmBit]; o++; }
    for (var inputNfPad = 0; inputNfPad < 2; inputNfPad++) { packet[o] <== 0; o++; }
    for (var inputNfBit = 253; inputNfBit >= 0; inputNfBit--) { packet[o] <== inputNfBits.out[inputNfBit]; o++; }
    for (var outputCmPad = 0; outputCmPad < 2; outputCmPad++) { packet[o] <== 0; o++; }
    for (var outputCmBit = 253; outputCmBit >= 0; outputCmBit--) { packet[o] <== outputCmBits.out[outputCmBit]; o++; }
    for (var recordBit = 0; recordBit < RECORD_BITS; recordBit++) { packet[o] <== recordBits[recordBit]; o++; }
    for (var boundaryByte = 0; boundaryByte < 8; boundaryByte++) { for (var boundaryBit = 7; boundaryBit >= 0; boundaryBit--) { packet[o] <== boundaryBits.out[8*boundaryByte + boundaryBit]; o++; } }
    for (var scriptHiBit = 127; scriptHiBit >= 0; scriptHiBit--) { packet[o] <== withdrawalScriptHiBits.out[scriptHiBit]; o++; }
    for (var scriptLoBit = 127; scriptLoBit >= 0; scriptLoBit--) { packet[o] <== withdrawalScriptLoBits.out[scriptLoBit]; o++; }
    for (var contextHiBit = 127; contextHiBit >= 0; contextHiBit--) { packet[o] <== contextHiBits.out[contextHiBit]; o++; }
    for (var contextLoBit = 127; contextLoBit >= 0; contextLoBit--) { packet[o] <== contextLoBits.out[contextLoBit]; o++; }
    component sha = Sha256(PACKET_BITS);
    for (var s = 0; s < PACKET_BITS; s++) { sha.in[s] <== packet[s]; }
    component digestHi = Bits2Num(128); component digestLo = Bits2Num(128);
    for (var t = 0; t < 128; t++) { digestHi.in[t] <== sha.out[127-t]; digestLo.in[t] <== sha.out[255-t]; }
    publicDigestHi === digestHi.out; publicDigestLo === digestLo.out;
}

component main {public [publicDigestHi, publicDigestLo]} = G1Relation();
