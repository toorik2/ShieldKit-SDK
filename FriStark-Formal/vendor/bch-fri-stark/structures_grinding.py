# Grinding / proof-of-work soundness check for FRI (tested).
# Verifier requires SHA256(transcript || nonce) to have `zbytes` leading zero bytes.
# This raises the cost of grinding attacks on FRI query soundness, letting a prover
# use fewer queries for the same security target.
import os, hashlib
from cashvm import VM, P, N, OP, decode_num, VMError

GRIND_FID = b"\x30"
def grind_body(zbytes):
    return [
        OP("CAT"),                 # transcript || nonce
        OP("SHA256"),
        N(zbytes), OP("SPLIT"),    # [prefix(zbytes), rest]
        OP("DROP"),                # drop rest
        P(b"\x00" * zbytes), OP("EQUALVERIFY"),
    ]

def find_nonce(transcript, zbytes):
    i = 0
    while True:
        nonce = i.to_bytes(8, "little")
        if hashlib.sha256(transcript + nonce).digest()[:zbytes] == b"\x00" * zbytes:
            return nonce
        i += 1

def run(transcript, nonce, zbytes):
    from cashvm import DEFINE
    prog = [P(transcript), P(nonce), P(GRIND_FID), DEFINE(grind_body(zbytes)),
            P(GRIND_FID), OP("INVOKE")]
    VM().run(prog)

# tests: zbytes=2 (16 bits of PoW)
transcript = os.urandom(32)
nonce = find_nonce(transcript, 2)
run(transcript, nonce, 2)
print(f"grinding: valid 16-bit PoW nonce {nonce.hex()} -> ACCEPTED")

# negative: wrong nonce must fail
try:
    run(transcript, os.urandom(8), 2); print("ERROR not rejected")
except VMError:
    print("grinding: invalid nonce -> CORRECTLY REJECTED")
print("GRINDING STRUCTURE: PASS")
