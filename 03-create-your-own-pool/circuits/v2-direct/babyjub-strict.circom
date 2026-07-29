pragma circom 2.2.0;

include "common.circom";
include "../../../node_modules/circomlib/circuits/babyjub.circom";
include "../../../node_modules/circomlib/circuits/escalarmulany.circom";
include "../../../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../../../node_modules/circomlib/circuits/pointbits.circom";

// Exact prime-subgroup proof for an externally supplied BabyJub point.
// Given an on-curve cofactor preimage Q, proving P=[8]Q places P in the
// order-q subgroup because the full BabyJub group has order 8q.
template BabyJubPrimeSubgroupPointV2() {
    signal input x;
    signal input y;
    signal input cofactorPreimageX;
    signal input cofactorPreimageY;

    component pointOnCurve = BabyCheck();
    pointOnCurve.x <== x;
    pointOnCurve.y <== y;
    component preimageOnCurve = BabyCheck();
    preimageOnCurve.x <== cofactorPreimageX;
    preimageOnCurve.y <== cofactorPreimageY;

    component nonidentity = AssertNonZero();
    nonidentity.in <== x;

    component double1 = BabyDbl();
    component double2 = BabyDbl();
    component double3 = BabyDbl();
    double1.x <== cofactorPreimageX;
    double1.y <== cofactorPreimageY;
    double2.x <== double1.xout;
    double2.y <== double1.yout;
    double3.x <== double2.xout;
    double3.y <== double2.yout;
    double3.xout === x;
    double3.yout === y;
}
template BabyJubFixedBaseMulV2() {
    signal input scalar;
    signal output x;
    signal output y;

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component scalarBits = BabyJubScalarBits();
    scalarBits.scalar <== scalar;
    component multiply = EscalarMulFix(251, BASE8);
    for (var bit = 0; bit < 251; bit++) {
        multiply.e[bit] <== scalarBits.bits[bit];
    }
    x <== multiply.out[0];
    y <== multiply.out[1];
}

// The caller must separately prove that the base point is a nonidentity member
// of the prime subgroup.
template BabyJubVariableBaseMulV2() {
    signal input scalar;
    signal input baseX;
    signal input baseY;
    signal output x;
    signal output y;

    component scalarBits = BabyJubScalarBits();
    scalarBits.scalar <== scalar;
    component multiply = EscalarMulAny(251);
    multiply.p[0] <== baseX;
    multiply.p[1] <== baseY;
    for (var bit = 0; bit < 251; bit++) {
        multiply.e[bit] <== scalarBits.bits[bit];
    }
    x <== multiply.out[0];
    y <== multiply.out[1];
}

template PackBabyJubPointV2() {
    signal input x;
    signal input y;
    signal output bits[256];

    component packed = Point2Bits_Strict();
    packed.in[0] <== x;
    packed.in[1] <== y;
    for (var bit = 0; bit < 256; bit++) {
        bits[bit] <== packed.out[bit];
    }
}
