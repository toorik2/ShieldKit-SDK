"""
native_poseidon2.py -- HP1.3 (hash primitive) of PATHC_STANDARD_SHARD_MEASURE_BUILD.

Poseidon2 permutation over Goldilocks (t=12, x^7, R_F=8, R_P=22), implemented to
MATCH the HorizenLabs reference (Poseidon2 authors, ePrint 2023/323) EXACTLY,
  the poseidon2.rs permutation (matmul_m4/matmul_external/matmul_internal/sbox_p).
Correctness is proven by the official KAT (permutation([0,1,..,11]) -> known 12
outputs) in self_test(); if it matches, constants + permutation are correct.
NO invented values (RESEARCH_RULES). NO mocks.

Sponge for the CT-AIR hashes (cm/nf/owner/membership): width t=12 = rate 8 +
capacity 4 (Plonky2 config, GOLDILOCKS_NATIVE_HASH.md). Fixed-length inputs are
zero-padded to the rate; absorb adds into the rate lanes then permutes; squeeze
returns lane 0. The verifier AIR (HP2/HP3) constrains the SAME permutation +
sponge layout -> prover/shard consistent.
"""
from native_poseidon2_constants import P, WIDTH, D, ROUNDS_F, ROUNDS_P, MAT_DIAG12, RC

RATE = 8
CAPACITY = WIDTH - RATE  # 4
_RF_HALF = ROUNDS_F // 2  # 4 (rounds_f_beginning)
_ROUNDS = ROUNDS_F + ROUNDS_P  # 30


def _sbox_p(x):
    # x^7 = ((x^2)^2 * x^2) * x   (matches reference sbox_p d=7)
    x2 = (x * x) % P
    out = (x2 * x2) % P     # x^4
    out = (out * x2) % P    # x^6
    out = (out * x) % P     # x^7
    return out


def _matmul_m4(s):
    # cheap 4x4 MDS applied to each 4-element block (reference matmul_m4)
    for i in range(0, WIDTH, 4):
        t0 = (s[i] + s[i + 1]) % P
        t1 = (s[i + 2] + s[i + 3]) % P
        t2 = (2 * s[i + 1] + t1) % P
        t3 = (2 * s[i + 3] + t0) % P
        t4 = (4 * t1 + t3) % P
        t5 = (4 * t0 + t2) % P
        t6 = (t3 + t5) % P
        t7 = (t2 + t4) % P
        s[i] = t6
        s[i + 1] = t5
        s[i + 2] = t7
        s[i + 3] = t4


def _matmul_external(s):
    # t=12 external matrix: M4 per block, then add per-lane block-sum (reference)
    _matmul_m4(s)
    stored = [0, 0, 0, 0]
    t4 = WIDTH // 4
    for l in range(4):
        acc = s[l]
        for j in range(1, t4):
            acc = (acc + s[4 * j + l]) % P
        stored[l] = acc
    for i in range(WIDTH):
        s[i] = (s[i] + stored[i % 4]) % P


def _matmul_internal(s):
    # t=12 internal matrix: result[i] = s[i]*diag[i] + sum(s)   (reference)
    total = 0
    for v in s:
        total = (total + v) % P
    for i in range(WIDTH):
        s[i] = ((s[i] * MAT_DIAG12[i]) % P + total) % P


def permutation(state_in):
    """Poseidon2 permutation on a length-12 list of field elements."""
    assert len(state_in) == WIDTH
    s = [v % P for v in state_in]
    _matmul_external(s)                                   # initial linear layer
    for r in range(0, _RF_HALF):                          # 4 full rounds
        for i in range(WIDTH):
            s[i] = _sbox_p((s[i] + RC[r][i]) % P)
        _matmul_external(s)
    p_end = _RF_HALF + ROUNDS_P
    for r in range(_RF_HALF, p_end):                      # 22 partial rounds
        s[0] = _sbox_p((s[0] + RC[r][0]) % P)
        _matmul_internal(s)
    for r in range(p_end, _ROUNDS):                       # 4 full rounds
        for i in range(WIDTH):
            s[i] = _sbox_p((s[i] + RC[r][i]) % P)
        _matmul_external(s)
    return s


def permutation_trace(state_in):
    """Round-per-row AIR trace of the permutation. Returns (states, aux):
      states[0]   = state after the initial matmul_external,
      states[r+1] = state after round r (states[_ROUNDS] = permutation output),
      aux[r]      = {full, x2, x4, x6, y} for the S-box of round r (x^7 = x6*x;
                    full round: all 12 lanes active; partial: only lane 0; y =
                    post-S-box vector BEFORE the round's linear layer).
    The verifier AIR (HP2/HP3) constrains exactly this round function row-to-row."""
    s = [v % P for v in state_in]
    _matmul_external(s)
    states = [s[:]]
    aux = []
    p_end = _RF_HALF + ROUNDS_P
    for r in range(_ROUNDS):
        cur = states[r]
        full = (r < _RF_HALF) or (r >= p_end)
        x2 = [0] * WIDTH; x4 = [0] * WIDTH; x6 = [0] * WIDTH; y = [0] * WIDTH
        ns = cur[:]
        if full:
            for i in range(WIDTH):
                x = (cur[i] + RC[r][i]) % P
                a = (x * x) % P; b = (a * a) % P; c = (b * a) % P
                x2[i] = a; x4[i] = b; x6[i] = c; y[i] = (c * x) % P
                ns[i] = y[i]
            _matmul_external(ns)
        else:
            x = (cur[0] + RC[r][0]) % P
            a = (x * x) % P; b = (a * a) % P; c = (b * a) % P
            x2[0] = a; x4[0] = b; x6[0] = c; y[0] = (c * x) % P
            for i in range(1, WIDTH):
                y[i] = cur[i]
            ns[0] = y[0]
            _matmul_internal(ns)
        aux.append({"full": full, "x2": x2, "x4": x4, "x6": x6, "y": y})
        states.append(ns)
    return states, aux


def hash_to_1(inputs):
    """Sponge hash of an arbitrary-length field-element list -> 1 field element.
    rate=8, capacity=4, zero state init, zero-padding (fixed-length inputs)."""
    state = [0] * WIDTH
    items = [v % P for v in inputs]
    if not items:
        items = [0]
    # pad to a multiple of RATE
    pad = (-len(items)) % RATE
    items = items + [0] * pad
    for off in range(0, len(items), RATE):
        for i in range(RATE):
            state[i] = (state[i] + items[off + i]) % P
        state = permutation(state)
    return state[0]


def merkle_compress(a, b):
    """2-to-1 compression for the Poseidon2 Merkle membership tree (in-circuit)."""
    return hash_to_1([a, b])


# Official KAT (HorizenLabs poseidon2.rs::kats, POSEIDON2_GOLDILOCKS_12): the only
# trusted correctness oracle -- input [0,1,..,11] -> these exact 12 outputs.
_KAT_INPUT = list(range(WIDTH))
_KAT_EXPECTED = [
    0x01eaef96bdf1c0c1, 0x1f0d2cc525b2540c, 0x6282c1dfe1e0358d, 0xe780d721f698e1e6,
    0x280c0b6f753d833b, 0x1b942dd5023156ab, 0x43f0df3fcccb8398, 0xe8e8190585489025,
    0x56bdbf72f77ada22, 0x7911c32bf9dcd705, 0xec467926508fbe67, 0x6a50450ddf85a6ed,
]


def self_test():
    out = permutation(_KAT_INPUT)
    assert out == _KAT_EXPECTED, "Poseidon2 KAT MISMATCH:\n got=%s\n exp=%s" % (
        [hex(x) for x in out], [hex(x) for x in _KAT_EXPECTED])
    # round-per-row trace must reproduce the permutation (and the KAT) exactly
    states, aux = permutation_trace(_KAT_INPUT)
    assert len(states) == _ROUNDS + 1, "trace length %d != %d" % (len(states), _ROUNDS + 1)
    assert len(aux) == _ROUNDS, "aux length %d != %d" % (len(aux), _ROUNDS)
    assert states[-1] == _KAT_EXPECTED, "trace final state != KAT"
    # cross-check the trace vs the direct permutation on a non-KAT input
    inp = [(i * 7 + 3) % P for i in range(WIDTH)]
    st2, _ = permutation_trace(inp)
    assert st2[-1] == permutation(inp), "permutation_trace final != permutation"
    return True


if __name__ == "__main__":
    ok = self_test()
    print("HP1.3 Poseidon2/Goldilocks t=12 -- official KAT verified:", ok)
    print("  permutation([0..11])[0] = %#018x (expected %#018x)"
          % (permutation(_KAT_INPUT)[0], _KAT_EXPECTED[0]))
    print("  hash_to_1([1,2,3,4]) = %#018x" % hash_to_1([1, 2, 3, 4]))
    print("  merkle_compress(7,9) = %#018x" % merkle_compress(7, 9))
