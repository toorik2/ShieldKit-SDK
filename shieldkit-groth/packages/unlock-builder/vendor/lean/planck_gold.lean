/-
  planck_gold.lean — Planck's GOLD-REFERENCE interpreter over LeanBCH's executable VM.

  A thin compiled `lean_exe` (modeled on `xcheck_idxN.lean` / `conformance/Runner.lean`) that
  exposes the LeanBCH VM as a JSON-lines coprocess over stdin/stdout. Planck's Rust interpreter
  (`planck-interp`) differentials against THIS binary at M2 (10⁹-sample conformance) and M7 (floor
  cross-check), so it must be a FAITHFUL surface over the real Lean defs — it re-implements no
  semantics, it only marshals hex ⇄ `Bytes` and CALLS the model.

  ── Protocol ─────────────────────────────────────────────────────────────────────────────────
  One JSON request object per input line → one JSON response object per output line. Three verbs:

    {"v":"step","op":"<hexbyte>","data":"<hex>","stack":["<hex>",…],"alt":["<hex>",…]}
       → apply `VM.stepInstr op data { stack, alt }`
       → {"stack":[…],"alt":[…],"error":<null|"<errName>">}

    {"v":"eval","code":"<hex bytecode>","stack":["<hex>",…],"alt":["<hex>",…]}
       → `VM.run (instrs.size+1) { load code with stack, alt }`  (the exact fuel of `VM.eval`)
       → {"accepted":<bool>,"stack":[…],"alt":[…],"error":<null|"<errName>">}
       where `accepted` is the BCH clean-stack rule (mirrors `VM.cleanTruthy`):
       error = none ∧ control stack empty ∧ main stack = a single truthy item.

    {"v":"cost","code":"<hex bytecode>","epoch":"BCH_2026_05"|"BCH_2026_05_CONSENSUS"}
       → `VM.runMeter (instrs.size+1) (load code)`; `Cost.operationCost E metrics`
       → {"opCost":<nat>,"instr":<nat>,"sigChecks":<nat>,"hashIters":<nat>,
          "arith":<nat>,"pushed":<nat>,"error":<null|"<errName>">}
       (the five raw `Cost.Metrics` fields alongside the derived op-cost.)

  ── Scope (honest boundary — do NOT stub the rest) ───────────────────────────────────────────
  • `step`/`eval` run the KEYSTONE-PROVEN pure core `VM.stepInstr` / `VM.run` (Eval.lean). That
    core natively covers: all pushes, the 13-op stack-shuffle set, PICK/ROLL, alt-stack ops,
    unary/binary NUMERIC ops, EQUAL(VERIFY), MIN/MAX/WITHIN, CAT/SPLIT/BIN2NUM/NUM2BIN, byte-wise
    AND/OR/XOR, the native HASH ops (RIPEMD160/SHA1/SHA256/HASH160/HASH256), and inline control
    flow (IF/NOTIF/ELSE/ENDIF/VERIFY/RETURN/BEGIN/UNTIL). This is exactly the D-shuffle + D-num
    conformance surface (see CONFORMANCE.md).
  • The SIGNATURE ops (CHECKSIG/CHECKDATASIG/CHECKMULTISIG + *VERIFY) are OUT OF SCOPE by design:
    they require the secp256k1 oracle (unlinked) and the transaction context, and live only in
    `VM.stepInstrExt` (Extended.lean). Planck's alphabets exclude them. Under the pure verbs they
    would surface as `error:"unimplemented"` rather than a wrong answer (over-reject-safe).
  • Likewise the extended-only ops — OP_INVERT, the 2026 shift ops, OP_REVERSEBYTES, the
    introspection / CashToken ops (0xc0..0xd3), OP_DEFINE/OP_INVOKE, OP_CHECKLOCKTIMEVERIFY /
    OP_CHECKSEQUENCEVERIFY — are in `stepInstrExt` only (they read the `Program`/oracle). Under
    the pure verbs they return `error:"unimplemented"`. A future `stepExt`/`evalExt` verb would
    thread a `Program` + `Secp256k1.reject`; it is NOT built here (no fabricated tx context).
  • The extended CONSENSUS GUARDS that `stepInstrExt` layers over the pure core (result-size caps
    on CAT/arith, minimal-encoding + non-negativity enforcement on PICK/ROLL/SPLIT indices) are
    NOT applied by the `step` verb. Within the battery domains (numeric operands intByteLen ≤ 2,
    PICK/ROLL indices 0..MAXIDX minimally encoded) the two agree exactly; outside them they can
    differ — see the risk note in APPLY.md.

  Hex string values are assumed escape-free (they are pure `[0-9a-fA-F]` / ASCII verbs) — the
  minimal JSON reader below does not decode `\\` escapes, which conformance inputs never contain.
-/
import LeanBCH.VM.Meter
import LeanBCH.Epoch
import LeanBCH.Cost.Metrics

open LeanBCH LeanBCH.VM LeanBCH.Cost

/-! ## Hex ⇄ bytes (same nibble table as `xcheck_idxN.lean` / `conformance/Runner.lean`). -/

def hexNib (c : Char) : Nat :=
  if '0' ≤ c ∧ c ≤ '9' then c.toNat - '0'.toNat
  else if 'a' ≤ c ∧ c ≤ 'f' then c.toNat - 'a'.toNat + 10
  else if 'A' ≤ c ∧ c ≤ 'F' then c.toNat - 'A'.toNat + 10
  else 0

partial def hexToBytes : List Char → List UInt8
  | a :: b :: rest => UInt8.ofNat (hexNib a * 16 + hexNib b) :: hexToBytes rest
  | _              => []

def hexStrToBytes (s : String) : List UInt8 := hexToBytes s.toList

def nibHex (n : Nat) : Char :=
  if n < 10 then Char.ofNat (n + '0'.toNat) else Char.ofNat (n - 10 + 'a'.toNat)

def byteHex (b : UInt8) : String :=
  let n := b.toNat
  String.ofList [nibHex (n / 16), nibHex (n % 16)]

def bytesToHex (bs : List UInt8) : String := String.join (bs.map byteHex)

/-- A stack (`List Bytes`, head = TOP) as a JSON array of lowercase-hex strings. -/
def stackJson (st : List Bytes) : String :=
  "[" ++ String.intercalate "," (st.map (fun b => "\"" ++ bytesToHex b ++ "\"")) ++ "]"

/-! ## Minimal JSON reader — flat objects whose values are strings or arrays-of-strings. -/

inductive JVal where
  | str : String → JVal
  | arr : List String → JVal

partial def skipWs (cs : List Char) : List Char :=
  match cs with
  | c :: r => if c == ' ' || c == '\t' || c == '\n' || c == '\r' then skipWs r else cs
  | []     => []

partial def readStrGo (cs : List Char) (acc : List Char) : Option (String × List Char) :=
  match cs with
  | '"' :: r => some (String.ofList acc.reverse, r)
  | c :: r   => readStrGo r (c :: acc)
  | []       => none

/-- Read a `"…"` string; `cs` must start at the opening quote. -/
def readStr (cs : List Char) : Option (String × List Char) :=
  match cs with
  | '"' :: r => readStrGo r []
  | _        => none

/-- Read a `[ "…", "…" ]` array of strings. -/
partial def readArr (cs0 : List Char) (acc : List String) : Option (List String × List Char) :=
  let cs := skipWs cs0
  match cs with
  | ']' :: r => some (acc.reverse, r)
  | _ =>
    match readStr cs with
    | some (s, r) =>
      match skipWs r with
      | ',' :: r2 => readArr r2 (s :: acc)
      | ']' :: r2 => some ((s :: acc).reverse, r2)
      | _         => none
    | none => none

/-- Read one value: a string or an array of strings (no nested objects / numbers / bools). -/
def readVal (cs0 : List Char) : Option (JVal × List Char) :=
  let cs := skipWs cs0
  match cs with
  | '"' :: _ => (readStr cs).map (fun p => (JVal.str p.1, p.2))
  | '[' :: r => (readArr r []).map (fun p => (JVal.arr p.1, p.2))
  | _        => none

/-- Read the body of an object into an assoc list `[(key, value)]` (any key order). -/
partial def readObj (cs0 : List Char) (acc : List (String × JVal)) : Option (List (String × JVal)) :=
  let cs := skipWs cs0
  match cs with
  | '}' :: _ => some acc.reverse
  | _ =>
    match readStr cs with
    | some (key, r) =>
      match skipWs r with
      | ':' :: r2 =>
        match readVal r2 with
        | some (v, r3) =>
          match skipWs r3 with
          | ',' :: r4 => readObj r4 ((key, v) :: acc)
          | '}' :: _  => some ((key, v) :: acc).reverse
          | _         => none
        | none => none
      | _ => none
    | none => none

def parseObj (line : String) : Option (List (String × JVal)) :=
  match skipWs line.toList with
  | '{' :: r => readObj r []
  | _        => none

def getStr (o : List (String × JVal)) (k : String) : Option String :=
  (o.find? (fun p => p.1 == k)).bind (fun p => match p.2 with | .str s => some s | _ => none)

def getArr (o : List (String × JVal)) (k : String) : List String :=
  match (o.find? (fun p => p.1 == k)).map (·.2) with
  | some (JVal.arr l) => l
  | _                 => []

def parseStack (hs : List String) : List Bytes := hs.map hexStrToBytes

/-! ## Error naming — a stable string per `VM.Err` constructor (the wire vocabulary). -/

def errName : Err → String
  | .stackUnderflow        => "stackUnderflow"
  | .altUnderflow          => "altUnderflow"
  | .invalidOpcode         => "invalidOpcode"
  | .disabledOpcode        => "disabledOpcode"
  | .unbalancedConditional => "unbalancedConditional"
  | .verifyFailed          => "verifyFailed"
  | .opReturn              => "opReturn"
  | .malformedPush         => "malformedPush"
  | .numberTooLarge        => "numberTooLarge"
  | .itemTooLarge          => "itemTooLarge"
  | .minimalEncoding       => "minimalEncoding"
  | .budgetExceeded        => "budgetExceeded"
  | .divByZero             => "divByZero"
  | .unimplemented         => "unimplemented"
  | .invalidTxIndex        => "invalidTxIndex"
  | .functionIdExcessive   => "functionIdExcessive"
  | .functionIdRedefined   => "functionIdRedefined"
  | .functionIdUndefined   => "functionIdUndefined"
  | .malformedFunction     => "malformedFunction"
  | .controlStackDepth     => "controlStackDepth"
  | .memorySlots           => "memorySlots"

def errJson : Option Err → String
  | none   => "null"
  | some e => "\"" ++ errName e ++ "\""

/-! ## Epoch selection (the cost pins as data — Epoch.lean). -/

def parseEpoch (s : String) : Epoch :=
  if s == "BCH_2026_05_CONSENSUS" then BCH_2026_05_CONSENSUS else BCH_2026_05

/-! ## The three verb handlers — each CALLS the model, marshals nothing else. -/

def handleStep (o : List (String × JVal)) : String :=
  let op   := (hexStrToBytes ((getStr o "op").getD "")).headD 0
  let data := hexStrToBytes ((getStr o "data").getD "")
  let stk  := parseStack (getArr o "stack")
  let al   := parseStack (getArr o "alt")
  let s : State := { stack := stk, alt := al }
  let r := stepInstr op data s
  "{\"stack\":" ++ stackJson r.stack
    ++ ",\"alt\":" ++ stackJson r.alt
    ++ ",\"error\":" ++ errJson r.error ++ "}"

def handleEval (o : List (String × JVal)) : String :=
  let code := hexStrToBytes ((getStr o "code").getD "")
  let stk  := parseStack (getArr o "stack")
  let al   := parseStack (getArr o "alt")
  let s0   := load code
  let s1 : State := { s0 with stack := stk, alt := al }
  let r := run (s0.instrs.size + 1) s1
  let accepted :=
    r.error.isNone && r.ctrl.isEmpty && (match r.stack with | [x] => isTruthy x | _ => false)
  "{\"accepted\":" ++ (if accepted then "true" else "false")
    ++ ",\"stack\":" ++ stackJson r.stack
    ++ ",\"alt\":" ++ stackJson r.alt
    ++ ",\"error\":" ++ errJson r.error ++ "}"

def handleCost (o : List (String × JVal)) : String :=
  let code := hexStrToBytes ((getStr o "code").getD "")
  let E    := parseEpoch ((getStr o "epoch").getD "BCH_2026_05")
  let s0   := load code
  let r := runMeter (s0.instrs.size + 1) s0
  let m := r.metrics
  "{\"opCost\":" ++ toString (operationCost E m)
    ++ ",\"instr\":" ++ toString m.evaluatedInstructionCount
    ++ ",\"sigChecks\":" ++ toString m.signatureCheckCount
    ++ ",\"hashIters\":" ++ toString m.hashDigestIterations
    ++ ",\"arith\":" ++ toString m.arithmeticCost
    ++ ",\"pushed\":" ++ toString m.stackPushedBytes
    ++ ",\"error\":" ++ errJson r.error ++ "}"

def handleLine (line : String) : String :=
  match parseObj line with
  | none => "{\"error\":\"parse_error\"}"
  | some o =>
    match getStr o "v" with
    | some "step" => handleStep o
    | some "eval" => handleEval o
    | some "cost" => handleCost o
    | _           => "{\"error\":\"unknown_verb\"}"

/-- Stream requests: one response line per non-blank request line, flushed immediately so the
    binary works as a request/response coprocess (not a read-all-then-print batch). `getLine`
    returns "" only at EOF; a genuine blank line is "\n" and is skipped after trim. -/
partial def serve (stdin stdout : IO.FS.Stream) : IO Unit := do
  let line ← stdin.getLine
  if line.isEmpty then pure ()
  else
    let t := line.trim
    if !t.isEmpty then
      stdout.putStr (handleLine t ++ "\n")
      stdout.flush
    serve stdin stdout

def main : IO Unit := do
  let stdin  ← IO.getStdin
  let stdout ← IO.getStdout
  serve stdin stdout
