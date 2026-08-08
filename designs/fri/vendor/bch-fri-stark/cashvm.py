"""
cashvm.py  -- reference-SEMANTICS interpreter for the post-Layla Bitcoin Cash VM.

Scope of fidelity:
  * Implements the STACK EFFECTS and CONTROL FLOW exactly as specified by:
      - CHIP-2021-05 Loops      (OP_BEGIN / OP_UNTIL: "until top is non-zero")
      - CHIP-2025-05 Functions  (OP_DEFINE / OP_INVOKE, shared stack+altstack+table)
      - CHIP-2024-07 BigInt     (arbitrary-precision script numbers)
      - legacy + 2022 opcodes used here (OP_CAT, OP_SHA256, arithmetic, etc.)
  * Script numbers use the real CScriptNum encoding (LE, sign bit in MSB, minimal).
  * OP_MOD / OP_DIV truncate toward zero (sign follows dividend), as in BCH.

NOT modeled (out of scope, must be cross-checked on libauth `next` / BCHN VMB tests
before any mainnet use):
  * exact opcode byte encodings for OP_BEGIN/OP_UNTIL
  * VM Limits operation-cost / hashing / memory-slot budget accounting
  * consensus DoS limits

So: this proves the structures are ALGORITHMICALLY CORRECT and stack-consistent.
It does not prove they fit the per-input cost budget. That is a separate question.
"""

import hashlib

# ----- script number codec (CScriptNum, BigInt-extended) ---------------------

def encode_num(n: int) -> bytes:
    if n == 0:
        return b""
    neg = n < 0
    n = abs(n)
    out = bytearray()
    while n:
        out.append(n & 0xff)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)

def decode_num(b: bytes) -> int:
    if not b:
        return 0
    out = 0
    for i, byte in enumerate(b):
        out |= (byte & (0x7f if i == len(b) - 1 else 0xff)) << (8 * i)
    if b[-1] & 0x80:
        return -out
    return out

def as_bool(b: bytes) -> bool:
    # empty, 0x00.., or negative-zero (0x80) are false
    for i, byte in enumerate(b):
        if byte != 0:
            if i == len(b) - 1 and byte == 0x80:
                return False
            return True
    return False

def truncdiv(a: int, b: int) -> int:
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q

def truncmod(a: int, b: int) -> int:
    return a - truncdiv(a, b) * b

# ----- VM --------------------------------------------------------------------

class VMError(Exception):
    pass

class Func:
    """A function body: a list of tokens (models the immutable byte-vector body)."""
    __slots__ = ("tokens",)
    def __init__(self, tokens):
        self.tokens = tokens

class VM:
    def __init__(self, debug=False):
        self.s = []          # main stack (list of bytes)
        self.alt = []        # alternate stack
        self.ftable = {}     # function identifier (bytes) -> Func
        self.debug = debug
        self.steps = 0
        self.maxdepth = 0
        # --- VM-Limits cost accounting (CHIP-2021-05) ---
        self.op_cost = 0
        self.hash_iters = 0
        self.hash_cost = 192      # 192 standard / 64 consensus, per digest iteration

    @staticmethod
    def digest_iters(message_length, is_double=False):
        return 1 + ((message_length + 8) // 64) + (1 if is_double else 0)

    def _hash(self, msg, is_double):
        it = self.digest_iters(len(msg), is_double)
        self.hash_iters += it
        self.op_cost += self.hash_cost * it

    # stack helpers
    def push(self, b):
        assert isinstance(b, (bytes, bytearray))
        self.s.append(bytes(b))
        self.op_cost += len(b)   # stack-pushed bytes
    def pushn(self, n):
        enc = encode_num(n)
        self.s.append(enc)
        self.op_cost += len(enc)
    def pop(self):
        if not self.s:
            raise VMError("stack underflow")
        return self.s.pop()
    def popn(self):
        return decode_num(self.pop())

    def run(self, tokens):
        self._exec(tokens, depth=0)
        return self.s

    def _exec(self, tokens, depth):
        if depth > 100:
            raise VMError("control stack depth > 100 (invoke nesting)")
        pc = 0
        cond = []           # IF/ELSE/ENDIF execution chain
        loops = []          # stack of BEGIN program-counter indices
        n = len(tokens)
        while pc < n:
            self.steps += 1
            self.maxdepth = max(self.maxdepth, len(self.s) + len(self.alt))
            op = tokens[pc]
            kind = op[0]
            self.op_cost += 100        # base instruction cost (every evaluated op)
            executing = all(cond)

            # control flow first (must run even when skipping, to track nesting)
            if kind == "IF" or kind == "NOTIF":
                v = False
                if executing:
                    top = self.pop()
                    v = as_bool(top)
                    if kind == "NOTIF":
                        v = not v
                cond.append(v)
                pc += 1; continue
            if kind == "ELSE":
                if not cond: raise VMError("ELSE without IF")
                cond[-1] = not cond[-1]
                pc += 1; continue
            if kind == "ENDIF":
                if not cond: raise VMError("ENDIF without IF")
                cond.pop()
                pc += 1; continue
            if kind == "BEGIN":
                if executing:
                    loops.append(pc)
                pc += 1; continue
            if kind == "UNTIL":
                if executing:
                    if not loops: raise VMError("UNTIL without BEGIN")
                    v = self.pop()
                    if as_bool(v):
                        loops.pop()          # exit loop
                    else:
                        pc = loops[-1]       # jump to BEGIN; +1 below -> first body op
                pc += 1; continue

            if not executing:
                pc += 1; continue

            self._do(kind, op, depth)
            pc += 1

    def _do(self, kind, op, depth):
        s = self.s
        if kind == "PUSH":
            self.push(op[1]); return
        if kind == "PUSHN":
            self.pushn(op[1]); return
        # --- stack ops ---
        if kind == "DUP":   self.push(s[-1]); return
        if kind == "DROP":  self.pop(); return
        if kind == "2DROP": self.pop(); self.pop(); return
        if kind == "SWAP":  s[-1], s[-2] = s[-2], s[-1]; return
        if kind == "OVER":  self.push(s[-2]); return
        if kind == "ROT":   s[-3], s[-2], s[-1] = s[-2], s[-1], s[-3]; return
        if kind == "NIP":   del s[-2]; return
        if kind == "TUCK":  s.insert(-2, s[-1]); return
        if kind == "2DUP":  self.push(s[-2]); self.push(s[-1]); return
        if kind == "DEPTH": self.pushn(len(s)); return
        if kind == "PICK":  k = self.popn(); self.push(s[-1-k]); return
        if kind == "ROLL":  k = self.popn(); self.op_cost += k; self.push(s.pop(-1-k)); return
        if kind == "TOALT": self.alt.append(self.pop()); return
        if kind == "FROMALT":
            if not self.alt: raise VMError("altstack underflow")
            self.push(self.alt.pop()); return
        # --- splice/crypto ---
        if kind == "CAT":
            b = self.pop(); a = self.pop(); self.push(a + b); return
        if kind == "SPLIT":
            k = self.popn(); d = self.pop()
            if k < 0 or k > len(d): raise VMError("SPLIT oob")
            self.push(d[:k]); self.push(d[k:]); return
        if kind == "BIN2NUM":
            # re-encode a byte string as a minimal Script number (CHIP-2018 OP_BIN2NUM). The
            # deployable VM (libauth) rejects non-minimally-encoded numbers in arithmetic, so the
            # FS fragments must minimise the 8-byte hash slice (+0x00 sign pad) before MOD/LESSTHAN.
            self.pushn(decode_num(self.pop())); return
        if kind == "SIZE":
            self.pushn(len(s[-1])); return
        if kind == "SHA256":
            m = self.pop(); self._hash(m, False)
            self.push(hashlib.sha256(m).digest()); return
        if kind == "HASH256":
            m = self.pop(); self._hash(m, True)
            self.push(hashlib.sha256(hashlib.sha256(m).digest()).digest()); return
        # --- equality / verify ---
        if kind == "EQUAL":
            b = self.pop(); a = self.pop(); self.push(encode_num(1) if a == b else b""); return
        if kind == "EQUALVERIFY":
            b = self.pop(); a = self.pop()
            if a != b: raise VMError("EQUALVERIFY failed"); 
            return
        if kind == "VERIFY":
            if not as_bool(self.pop()): raise VMError("VERIFY failed")
            return
        if kind == "NUMEQUAL":
            b = self.popn(); a = self.popn(); self.push(encode_num(1) if a == b else b""); return
        if kind == "NUMEQUALVERIFY":
            b = self.popn(); a = self.popn()
            if a != b: raise VMError("NUMEQUALVERIFY failed")
            return
        # --- arithmetic (BigInt) ; cost: +2*result_len (encoding), +a*b for mul/div/mod ---
        def _alen(x): return len(encode_num(x))
        if kind == "ADD":
            b=self.popn(); a=self.popn(); r=a+b; self.pushn(r); self.op_cost += _alen(r); return
        if kind == "SUB":
            b=self.popn(); a=self.popn(); r=a-b; self.pushn(r); self.op_cost += _alen(r); return
        if kind == "MUL":
            b=self.popn(); a=self.popn(); r=a*b
            self.pushn(r); self.op_cost += _alen(r) + _alen(a)*_alen(b); return
        if kind == "DIV":
            b=self.popn(); a=self.popn()
            if b == 0: raise VMError("div by zero")
            r=truncdiv(a,b); self.pushn(r); self.op_cost += _alen(r) + _alen(a)*_alen(b); return
        if kind == "MOD":
            b=self.popn(); a=self.popn()
            if b == 0: raise VMError("mod by zero")
            r=truncmod(a,b); self.pushn(r); self.op_cost += _alen(r) + _alen(a)*_alen(b); return
        if kind == "1ADD": r=self.popn()+1; self.pushn(r); self.op_cost += _alen(r); return
        if kind == "1SUB": r=self.popn()-1; self.pushn(r); self.op_cost += _alen(r); return
        if kind == "NEGATE": r=-self.popn(); self.pushn(r); self.op_cost += _alen(r); return
        if kind == "NOT": self.push(encode_num(1) if self.popn() == 0 else b""); return
        if kind == "0NOTEQUAL": self.push(encode_num(1) if self.popn() != 0 else b""); return
        if kind == "LESSTHAN": b=self.popn(); a=self.popn(); self.push(encode_num(1) if a<b else b""); return
        if kind == "GREATERTHAN": b=self.popn(); a=self.popn(); self.push(encode_num(1) if a>b else b""); return
        if kind == "BOOLAND": b=self.popn(); a=self.popn(); self.push(encode_num(1) if (a!=0 and b!=0) else b""); return
        # --- functions ---
        if kind == "DEFINE":
            fid = self.pop()
            if len(fid) > 7: raise VMError("function id length > 7")
            body = op[1]                 # Func object captured at assemble time
            if fid in self.ftable: raise VMError("function already defined")
            self.ftable[fid] = body
            return
        if kind == "INVOKE":
            fid = self.pop()
            if fid not in self.ftable: raise VMError("undefined function")
            self._exec(self.ftable[fid].tokens, depth + 1)   # shares stack/alt/table
            return
        raise VMError("unimplemented op: %s" % kind)


# ----- tiny assembler: human tokens -> VM tokens -----------------------------
# Each token is a tuple. Pushes: ("PUSH", bytes) / ("PUSHN", int).

def P(b):    return ("PUSH", b)
def N(i):    return ("PUSHN", i)
def OP(name): return (name,)
def DEFINE(body_tokens): return ("DEFINE", Func(body_tokens))
