pragma circom 2.2.0;

include "common.circom";
include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template MerkleRoot32(nodeDomain) {
    signal input leaf;
    signal input indexBits[32];
    signal input siblings[32];
    signal output root;

    signal nodes[33];
    signal left[32];
    signal right[32];
    component hashers[32];
    component indexBitChecks[32];

    nodes[0] <== leaf;
    for (var level = 0; level < 32; level++) {
        indexBitChecks[level] = AssertBoolean();
        indexBitChecks[level].in <== indexBits[level];

        left[level] <==
            nodes[level]
            + indexBits[level] * (siblings[level] - nodes[level]);
        right[level] <==
            siblings[level]
            + indexBits[level] * (nodes[level] - siblings[level]);

        hashers[level] = Poseidon(3);
        hashers[level].inputs[0] <== nodeDomain;
        hashers[level].inputs[1] <== left[level];
        hashers[level].inputs[2] <== right[level];
        nodes[level + 1] <== hashers[level].out;
    }
    root <== nodes[32];
}

template NoteMembershipV2() {
    signal input enabled;
    signal input expectedRoot;
    signal input leaf;
    signal input index;
    signal input siblings[32];

    component enabledBit = AssertBoolean();
    enabledBit.in <== enabled;

    component indexBits = NumToBits32();
    indexBits.in <== index;
    component path = MerkleRoot32(
        0x06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153
    );
    path.leaf <== leaf;
    for (var level = 0; level < 32; level++) {
        path.indexBits[level] <== indexBits.bits[level];
        path.siblings[level] <== siblings[level];
    }
    (path.root - expectedRoot) * enabled === 0;
}

template NoteAppendV2() {
    signal input enabled;
    signal input preRoot;
    signal input postRoot;
    signal input outputLeaf;
    signal input appendIndex;
    signal input siblings[32];

    component enabledBit = AssertBoolean();
    enabledBit.in <== enabled;
    component indexBits = NumToBits32();
    indexBits.in <== appendIndex;

    component before = MerkleRoot32(
        0x06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153
    );
    component after = MerkleRoot32(
        0x06a305c7bcf59e063a048eb6d2d870018d0051268abe747a3ddde39daf1b2153
    );
    // Pinned KAT:
    // Poseidon(NOTE_TREE_EMPTY_DOMAIN, 0).
    before.leaf <==
        0x24fda6f2c3c9b7492e55e47bc6adc8041391570282c3c6cf97329abd31128081;
    after.leaf <== outputLeaf;
    for (var level = 0; level < 32; level++) {
        before.indexBits[level] <== indexBits.bits[level];
        after.indexBits[level] <== indexBits.bits[level];
        before.siblings[level] <== siblings[level];
        after.siblings[level] <== siblings[level];
    }
    (before.root - preRoot) * enabled === 0;
    (after.root - postRoot) * enabled === 0;
}

template IndexedNullifierLeafV2() {
    signal input leafType;
    signal input physicalIndex;
    signal input key;
    signal input successorIndex;
    signal input successorKey;
    signal output hash;

    component poseidon = Poseidon(6);
    poseidon.inputs[0] <==
        0x21e0792dda012608a23ccef2acfb69f6a5d8ea940de6399bdd1094d68e4ffce2;
    poseidon.inputs[1] <== leafType;
    poseidon.inputs[2] <== physicalIndex;
    poseidon.inputs[3] <== key;
    poseidon.inputs[4] <== successorIndex;
    poseidon.inputs[5] <== successorKey;
    hash <== poseidon.out;
}

// Proves the exact sequential update used by the indexed tree:
// predecessor pointer replacement, then append into a proven empty leaf.
template IndexedNullifierInsertionV2() {
    signal input enabled;
    signal input preRoot;
    signal input postRoot;
    signal input nullifier;
    signal input appendIndex;

    signal input predecessorType;
    signal input predecessorIndex;
    signal input predecessorKey;
    signal input predecessorSuccessorIndex;
    signal input predecessorSuccessorKey;
    signal input predecessorPath[32];
    signal input appendPath[32];

    component enabledBit = AssertBoolean();
    enabledBit.in <== enabled;

    // Active predecessors are exactly MIN (1) or NORMAL (2).
    component predecessorMinCheck = IsEqual();
    predecessorMinCheck.in[0] <== predecessorType;
    predecessorMinCheck.in[1] <== 1;
    component predecessorNormalCheck = IsEqual();
    predecessorNormalCheck.in[0] <== predecessorType;
    predecessorNormalCheck.in[1] <== 2;
    signal activeMin;
    signal activeNormal;
    activeMin <== enabled * predecessorMinCheck.out;
    activeNormal <== enabled * predecessorNormalCheck.out;
    activeMin + activeNormal === enabled;

    component appendIndexBits = NumToBits32();
    appendIndexBits.in <== appendIndex;
    component predecessorIndexBits = NumToBits32();
    predecessorIndexBits.in <== predecessorIndex;
    // This is not implied by LessThan below for an unconstrained Fr witness:
    // without an explicit u32 decomposition, a field-alias value can make the
    // comparator's modular difference appear small.
    component successorIndexBits = NumToBits32();
    successorIndexBits.in <== predecessorSuccessorIndex;
    component appendBelowTwo = LessThan(32);
    appendBelowTwo.in[0] <== appendIndex;
    appendBelowTwo.in[1] <== 2;
    appendBelowTwo.out * enabled === 0;

    predecessorIndex * activeMin === 0;
    predecessorKey * activeMin === 0;

    component predecessorBelowTwo = LessThan(32);
    predecessorBelowTwo.in[0] <== predecessorIndex;
    predecessorBelowTwo.in[1] <== 2;
    predecessorBelowTwo.out * activeNormal === 0;
    component predecessorBeforeAppend = LessThan(32);
    predecessorBeforeAppend.in[0] <== predecessorIndex;
    predecessorBeforeAppend.in[1] <== appendIndex;
    predecessorBeforeAppend.out * activeNormal === activeNormal;

    component nullifierBits = Num2Bits_strict();
    nullifierBits.in <== nullifier;
    component predecessorKeyBits = Num2Bits_strict();
    predecessorKeyBits.in <== predecessorKey;
    component successorKeyBits = Num2Bits_strict();
    successorKeyBits.in <== predecessorSuccessorKey;

    component predecessorBeforeNullifier = BitsLessThan(254);
    component nullifierBeforeSuccessor = BitsLessThan(254);
    for (var bit = 0; bit < 254; bit++) {
        predecessorBeforeNullifier.left[bit] <== predecessorKeyBits.out[bit];
        predecessorBeforeNullifier.right[bit] <== nullifierBits.out[bit];
        nullifierBeforeSuccessor.left[bit] <== nullifierBits.out[bit];
        nullifierBeforeSuccessor.right[bit] <== successorKeyBits.out[bit];
    }
    predecessorBeforeNullifier.less * activeNormal === activeNormal;

    component successorMaxCheck = IsEqual();
    successorMaxCheck.in[0] <== predecessorSuccessorIndex;
    successorMaxCheck.in[1] <== 1;
    component successorSelfCheck = IsEqual();
    successorSelfCheck.in[0] <== predecessorSuccessorIndex;
    successorSelfCheck.in[1] <== predecessorIndex;
    successorSelfCheck.out * enabled === 0;
    signal activeMaxSuccessor;
    signal activeNormalSuccessor;
    activeMaxSuccessor <== enabled * successorMaxCheck.out;
    activeNormalSuccessor <== enabled * (1 - successorMaxCheck.out);
    predecessorSuccessorKey * activeMaxSuccessor === 0;

    component successorBelowTwo = LessThan(32);
    successorBelowTwo.in[0] <== predecessorSuccessorIndex;
    successorBelowTwo.in[1] <== 2;
    successorBelowTwo.out * activeNormalSuccessor === 0;
    component successorBeforeAppend = LessThan(32);
    successorBeforeAppend.in[0] <== predecessorSuccessorIndex;
    successorBeforeAppend.in[1] <== appendIndex;
    successorBeforeAppend.out * activeNormalSuccessor === activeNormalSuccessor;
    nullifierBeforeSuccessor.less * activeNormalSuccessor === activeNormalSuccessor;

    component predecessorLeaf = IndexedNullifierLeafV2();
    predecessorLeaf.leafType <== predecessorType;
    predecessorLeaf.physicalIndex <== predecessorIndex;
    predecessorLeaf.key <== predecessorKey;
    predecessorLeaf.successorIndex <== predecessorSuccessorIndex;
    predecessorLeaf.successorKey <== predecessorSuccessorKey;

    component updatedPredecessorLeaf = IndexedNullifierLeafV2();
    updatedPredecessorLeaf.leafType <== predecessorType;
    updatedPredecessorLeaf.physicalIndex <== predecessorIndex;
    updatedPredecessorLeaf.key <== predecessorKey;
    updatedPredecessorLeaf.successorIndex <== appendIndex;
    updatedPredecessorLeaf.successorKey <== nullifier;

    component predecessorBeforePath = MerkleRoot32(
        0x241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4
    );
    component predecessorAfterPath = MerkleRoot32(
        0x241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4
    );
    predecessorBeforePath.leaf <== predecessorLeaf.hash;
    predecessorAfterPath.leaf <== updatedPredecessorLeaf.hash;
    for (var level = 0; level < 32; level++) {
        predecessorBeforePath.indexBits[level] <== predecessorIndexBits.bits[level];
        predecessorAfterPath.indexBits[level] <== predecessorIndexBits.bits[level];
        predecessorBeforePath.siblings[level] <== predecessorPath[level];
        predecessorAfterPath.siblings[level] <== predecessorPath[level];
    }
    (predecessorBeforePath.root - preRoot) * enabled === 0;

    component newLeaf = IndexedNullifierLeafV2();
    newLeaf.leafType <== 2;
    newLeaf.physicalIndex <== appendIndex;
    newLeaf.key <== nullifier;
    newLeaf.successorIndex <== predecessorSuccessorIndex;
    newLeaf.successorKey <== predecessorSuccessorKey;

    component emptyAppendPath = MerkleRoot32(
        0x241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4
    );
    component newAppendPath = MerkleRoot32(
        0x241df03119348914e68c8b8c34a7c35acea16196c2d1c23223f4a191007175a4
    );
    // Pinned KAT:
    // Poseidon(NULLIFIER_TREE_EMPTY_DOMAIN, 0).
    emptyAppendPath.leaf <==
        0x18df533689e5101f3e88e6e91339f278f68a84c86f22997b1bb28be7dec598a6;
    newAppendPath.leaf <== newLeaf.hash;
    for (var level = 0; level < 32; level++) {
        emptyAppendPath.indexBits[level] <== appendIndexBits.bits[level];
        newAppendPath.indexBits[level] <== appendIndexBits.bits[level];
        emptyAppendPath.siblings[level] <== appendPath[level];
        newAppendPath.siblings[level] <== appendPath[level];
    }

    (emptyAppendPath.root - predecessorAfterPath.root) * enabled === 0;
    (newAppendPath.root - postRoot) * enabled === 0;
}
