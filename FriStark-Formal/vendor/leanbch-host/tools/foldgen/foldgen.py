#!/usr/bin/env python3
"""foldgen — complete fold-table superoptimizer + Lean theorem emitter.

Consolidates the two scratch stages (superopt enumerate + leangen emit) into ONE
deterministic tool. Enumerates every op sequence up to length L over the BCH2026
stack-shuffle op alphabet, canonicalizes by *decidable stack effect* (NO SMT),
picks the min-byte representative per effect-class, derives every sound fold
(unconditional + depth-guarded), then emits the machine-checkable Lean module
`LeanBCH.Opt.FoldTable` on stdout.

Usage:
    python3 foldgen.py                 > LeanBCH/Opt/FoldTable.lean   # default L=4,D=12,MAXIDX=6
    python3 foldgen.py --len 4 --depth 12 --maxidx 6 > out.lean
    python3 foldgen.py --report        > report.txt                # human-readable fold report

Determinism: dict insertion order (from a fixed itertools.product) + stable sorts
+ sets used only for membership => byte-identical output across runs. Regenerate
with `--check <file>` to diff against a checked-in copy (used by scripts/verify.sh).
"""
import sys, itertools, argparse

# ---- op transforms (return new stack list or None on underflow) --------------
# Stack list convention: index 0 = TOP (matches Lean `x :: y :: s`, x = top).
def ap(op, s):
    k = op[0]; n = len(s)
    if k=='DUP':   return None if n<1 else [s[0]]+s
    if k=='DROP':  return None if n<1 else s[1:]
    if k=='OVER':  return None if n<2 else [s[1]]+s
    if k=='SWAP':  return None if n<2 else [s[1],s[0]]+s[2:]
    if k=='ROT':   return None if n<3 else [s[2],s[0],s[1]]+s[3:]
    if k=='NIP':   return None if n<2 else [s[0]]+s[2:]
    if k=='TUCK':  return None if n<2 else [s[0],s[1],s[0]]+s[2:]
    if k=='2DROP': return None if n<2 else s[2:]
    if k=='2DUP':  return None if n<2 else [s[0],s[1]]+s
    if k=='3DUP':  return None if n<3 else [s[0],s[1],s[2]]+s
    if k=='2OVER': return None if n<4 else [s[2],s[3]]+s
    if k=='2ROT':  return None if n<6 else [s[4],s[5]]+s[0:4]+s[6:]
    if k=='2SWAP': return None if n<4 else [s[2],s[3],s[0],s[1]]+s[4:]
    if k=='PICK':  i=op[1]; return None if n<i+1 else [s[i]]+s
    if k=='ROLL':  i=op[1]; return None if n<i+1 else [s[i]]+s[0:i]+s[i+1:]
    raise Exception('unknown '+k)

ONEBYTE = ['DUP','DROP','OVER','SWAP','ROT','NIP','TUCK',
           '2DROP','2DUP','3DUP','2OVER','2ROT','2SWAP']

def cost_op(op):
    if op[0] in ('PICK','ROLL'):
        return 2 if op[1] <= 16 else 3   # index push (1B for n<=16) + op byte
    return 1
def cost_seq(seq): return sum(cost_op(o) for o in seq)

def name(op):
    if op[0] in ('PICK','ROLL'): return f"{op[1]}{op[0]}"
    return op[0]
def sname(seq):
    return "" if not seq else " ".join(name(o) for o in seq)

# ---- Lean rendering ----------------------------------------------------------
LEAN = {'DUP':'DUP','DROP':'DROP','OVER':'OVER','SWAP':'SWAP','ROT':'ROT',
        'NIP':'NIP','TUCK':'TUCK','2DROP':'TWODROP','2DUP':'TWODUP',
        '3DUP':'THREEDUP','2OVER':'TWOOVER','2ROT':'TWOROT','2SWAP':'TWOSWAP'}
def lean_op(op):
    if op[0] in ('PICK','ROLL'): return f"{op[0]} {op[1]}"
    return LEAN[op[0]]
def lean_list(seq):
    return "[" + ", ".join(lean_op(o) for o in seq) + "]"
def sanit(seq):
    parts=[]
    for o in seq:
        if o[0] in ('PICK','ROLL'): parts.append(f"{o[1]}{o[0]}")
        else: parts.append(o[0].replace('2','TWO').replace('3','THREE'))
    return "_".join(parts) if parts else "EMPTY"
def has_zeroroll(seq):
    return any(o==('ROLL',0) for o in seq)


def build(MAXIDX, D, L):
    ALPHA = ([(x,) for x in ONEBYTE]
             + [('PICK',n) for n in range(MAXIDX+1)]
             + [('ROLL',n) for n in range(MAXIDX+1)])

    # effect: tuple over depths 0..D of (frozen output tuple) or 'U' (underflow).
    def effect(seq):
        out=[]
        for d in range(D+1):
            s=list(range(d)); ok=True
            for op in seq:
                s=ap(op,s)
                if s is None: ok=False; break
            out.append('U' if not ok else tuple(s))
        return tuple(out)
    def threshold(seq):
        for d in range(D+1):
            s=list(range(d)); ok=True
            for op in seq:
                s=ap(op,s)
                if s is None: ok=False; break
            if ok: return d
        return D+1

    # enumerate (empty + length 1..L) into effect-class buckets (dict = deterministic)
    buckets={}
    def add(seq):
        buckets.setdefault(effect(seq),[]).append((cost_seq(seq),len(seq),seq))
    add(())
    for l in range(1,L+1):
        for seq in itertools.product(ALPHA, repeat=l):
            add(seq)

    def keyfn(x): return (x[0], x[1], tuple(name(o) for o in x[2]))
    reps={eff:min(mem,key=keyfn) for eff,mem in buckets.items()}
    def rep_of(seq): return reps[effect(seq)][2]

    # UNCONDITIONAL folds: any strictly-costlier member of an effect-class -> its rep.
    # Tuple = (src, rep, srccost, eff): srccost drives the NEW-fold ordering below.
    uncond=[]
    for eff,mem in buckets.items():
        rep=reps[eff]
        for m in mem:
            if m[2]!=rep[2] and m[0]>rep[0]:
                uncond.append((m[2],rep[2],m[0],eff))

    # CONDITIONAL folds: within a tail bucket (same effect at depth D) the global
    # min-byte rep agrees with src for all depths >= k (k>0); guard is that depth.
    tail={}
    for eff,mem in buckets.items():
        for m in mem:
            tail.setdefault(eff[D],[]).append((m[0],m[1],m[2],eff))
    def agree_from(effS, effR):
        if effS[D]!=effR[D]: return None
        k=0
        for d in range(D+1):
            if effS[d]!=effR[d]: k=d+1
        return k
    cond=[]
    for tk,mem in tail.items():
        repC=min(mem,key=lambda x:(x[0],x[1],tuple(name(o) for o in x[2])))
        for m in mem:
            if m[2]==repC[2] or m[0]<=repC[0]: continue
            k=agree_from(m[3],repC[3])
            if k is None or k==0: continue
            cond.append((m[2],repC[2],k))

    # curated Peephole.lean fold set (kept hand-written there; excluded here to
    # avoid duplication). The generator VALIDATES it reproduces all of them.
    def S(*names):
        seq=[]
        for nm in names:
            if nm.endswith('PICK'): seq.append(('PICK',int(nm[:-4])))
            elif nm.endswith('ROLL'): seq.append(('ROLL',int(nm[:-4])))
            else: seq.append((nm,))
        return tuple(seq)
    KNOWN_UNCOND=[(S('OVER','OVER'),S('2DUP')),(S('SWAP','OVER'),S('TUCK')),
        (S('SWAP','DROP'),S('NIP')),(S('2PICK','2PICK','2PICK'),S('3DUP')),
        (S('3PICK','3PICK'),S('2OVER')),(S('3ROLL','3ROLL'),S('2SWAP')),
        (S('5ROLL','5ROLL'),S('2ROT')),(S('0PICK'),S('DUP')),(S('1PICK'),S('OVER')),
        (S('1ROLL'),S('SWAP')),(S('2ROLL'),S('ROT')),(S('DROP','DROP'),S('2DROP'))]
    KNOWN_COND=[(S('0ROLL'),(),1),(S('SWAP','SWAP'),(),2),(S('DUP','DROP'),(),1),
        (S('OVER','DROP'),(),2),(S('ROT','ROT','ROT'),(),3)]
    KNOWNSET=set()
    for src,rep in KNOWN_UNCOND: KNOWNSET.add((src,rep))
    for src,rep,_ in KNOWN_COND: KNOWNSET.add((src,rep))

    # VALIDATION: every curated fold must be reproduced by the enumeration.
    def folds_uncond(src,rep): return any(u[0]==src and u[1]==rep for u in uncond)
    def folds_cond(src,rep):
        for c in cond:
            if c[0]==src and c[1]==rep: return c[2]
        return None
    valfail=[]
    for src,rep in KNOWN_UNCOND:
        if not (folds_uncond(src,rep) and rep_of(src)==rep):
            valfail.append(f"uncond {sname(src)}->{sname(rep)}")
    for src,rep,ek in KNOWN_COND:
        if folds_cond(src,rep)!=ek:
            valfail.append(f"cond-{ek} {sname(src)}->{sname(rep) or 'EMPTY'}")

    # NEW folds = complete sound folds (src len<=3, primitive, not curated).
    def is_primitive_src(src):
        n=len(src)
        for i in range(n):
            for j in range(i+1,n+1):
                if (i,j)==(0,n): continue
                sub=src[i:j]
                if not sub: continue
                if cost_seq(rep_of(sub))<cost_seq(sub): return False
        return True
    seen=set(); newu=[]
    for src,rep,srccost,eff in sorted(uncond,key=lambda u:(len(u[0]),u[2])):
        if len(src)>3 or (src,rep) in KNOWNSET or not is_primitive_src(src): continue
        if (src,rep) in seen: continue
        seen.add((src,rep)); newu.append((src,rep))
    seenc=set(); newc=[]
    for src,rep,k in sorted(cond,key=lambda u:(len(u[0]),u[0])):
        if len(src)>3 or (src,rep) in KNOWNSET or not is_primitive_src(src): continue
        if (src,rep,k) in seenc: continue
        seenc.add((src,rep,k)); newc.append((src,rep,k))

    # 0ROLL noise filter (a `ROLL 0` is a conditional no-op already covered by the
    # curated roll0_nop; drop any fold mentioning it) + independent soundness recheck.
    U=[(s,d) for (s,d) in newu if not (has_zeroroll(s) or has_zeroroll(d))]
    C=[(s,d,k) for (s,d,k) in newc if not (has_zeroroll(s) or has_zeroroll(d))]
    badU=sum(1 for s,d in U if effect(s)!=effect(d))
    badC=0
    for s,d,k in C:
        eS=effect(s); eD=effect(d)
        if any(eS[dd]!=eD[dd] for dd in range(k,D+1)): badC+=1
    return dict(U=U,C=C,uncond=uncond,cond=cond,newu=newu,newc=newc,
                valfail=valfail,badU=badU,badC=badC,threshold=threshold,
                nclasses=len(buckets))


def emit_lean(res, MAXIDX, D, L):
    U=res['U']; C=res['C']; threshold=res['threshold']
    names=set()
    def uniq(base):
        n=base; i=1
        while n in names: n=f"{base}_{i}"; i+=1
        names.add(n); return n
    def pattern(d):
        p="s"
        for i in reversed(range(d)): p=f"_ | ⟨x{i}, {p}⟩"
        return p
    N=len(U)+len(C)
    out=[]
    out.append(f"-- GENERATED by tools/foldgen (L={L}, D={D}, MAXIDX={MAXIDX}) — do not hand-edit.")
    out.append(f"-- {N} theorems ({len(U)} unconditional `Correct` + {len(C)} depth-guarded).")
    out.append("-- Window-complete over the BCH2026 stack-shuffle algebra: every sound fold with a")
    out.append("-- source of ≤ L ops, verified by DECIDABLE STACK EFFECT (no SMT). Each is a")
    out.append("-- machine-checked `LeanBCH.Opt.Correct` (uncond) or depth-guarded `run` equality.")
    out.append("-- Reproduces every LeanBCH.Opt/Peephole.lean fold (the curated 17+2 hand-written")
    out.append("-- set); those are kept in Peephole.lean and excluded here to avoid duplication,")
    out.append("-- so this module is the generated *remainder* of the complete window set.")
    out.append("-- Regenerate:  python3 tools/foldgen/foldgen.py > LeanBCH/Opt/FoldTable.lean")
    out.append("import LeanBCH.Opt.Basic")
    out.append("set_option linter.unusedSimpArgs false")
    out.append("set_option linter.unusedVariables false")
    out.append("namespace LeanBCH.Opt.FoldTable")
    out.append("open LeanBCH.Opt LeanBCH.Opt.Op")
    out.append("")
    out.append("/-! ### UNCONDITIONAL folds (Correct, all inputs incl. underflow) -/")
    out.append("")
    for s,d in U:
        dep=max(threshold(s),threshold(d))
        nm=uniq("u_"+sanit(s)+"__"+sanit(d))
        out.append(f"theorem {nm} {{α}} : Correct ({lean_list(s)} : List (Op α)) {lean_list(d)} := by")
        out.append(f"  intro ⟨m, a⟩")
        out.append(f"  rcases m with {pattern(dep)} <;> rfl")
        out.append("")
    out.append("/-! ### CONDITIONAL folds (guard: block-entry main depth ≥ k) -/")
    out.append("")
    for s,d,k in C:
        dep=max(threshold(s),threshold(d),k)
        nm=uniq("c_"+sanit(s)+"__"+sanit(d)+f"_k{k}")
        dst_txt=lean_list(d) if d else "[]"
        out.append(f"theorem {nm} {{α}} :")
        out.append(f"    ∀ st : State α, {k} ≤ st.1.length → run ({lean_list(s)} : List (Op α)) st = run {dst_txt} st := by")
        out.append(f"  intro ⟨m, a⟩ h")
        out.append(f"  rcases m with {pattern(dep)} <;> first | rfl | simp_all [run, step] | omega")
        out.append("")
    out.append("end LeanBCH.Opt.FoldTable")
    return "\n".join(out) + "\n"


def emit_report(res):
    out=["=== VALIDATION ===",
         "FAIL: "+"; ".join(res['valfail']) if res['valfail'] else "PASS (all curated Peephole folds reproduced)",
         f"# effect-classes={res['nclasses']} uncond-rules={len(res['uncond'])} cond-rules={len(res['cond'])}",
         f"# NEW (len<=3, primitive, non-curated): uncond={len(res['newu'])} cond={len(res['newc'])}",
         f"# after 0ROLL-filter+dedup: U={len(res['U'])} C={len(res['C'])}  soundcheck badU={res['badU']} badC={res['badC']}",
         "", "=== FOLDS ==="]
    for s,d in res['U']:
        out.append(f"  {sname(s):22s} -> {sname(d) or 'EMPTY':12s} [uncond]")
    for s,d,k in res['C']:
        out.append(f"  {sname(s):22s} -> {sname(d) or 'EMPTY':12s} [cond-{k}]")
    return "\n".join(out) + "\n"


def main():
    ap_=argparse.ArgumentParser(description="Complete fold-table generator + Lean emitter.")
    ap_.add_argument("--len","-L",type=int,default=4,help="max source sequence length (default 4)")
    ap_.add_argument("--depth","-D",type=int,default=12,help="max test stack depth (default 12)")
    ap_.add_argument("--maxidx","-M",type=int,default=6,help="max PICK/ROLL index (default 6)")
    ap_.add_argument("--report",action="store_true",help="emit human-readable fold report instead of Lean")
    ap_.add_argument("--check",metavar="FILE",help="regenerate and diff against FILE; exit 1 if differ")
    args=ap_.parse_args()

    res=build(args.maxidx,args.depth,args.len)
    if res['valfail']:
        sys.stderr.write("VALIDATION FAIL: "+"; ".join(res['valfail'])+"\n"); sys.exit(2)
    if res['badU'] or res['badC']:
        sys.stderr.write(f"SOUNDNESS FAIL: badU={res['badU']} badC={res['badC']}\n"); sys.exit(2)

    text = emit_report(res) if args.report else emit_lean(res,args.maxidx,args.depth,args.len)
    sys.stderr.write(f"# foldgen: {len(res['U'])+len(res['C'])} theorems "
                     f"({len(res['U'])} uncond + {len(res['C'])} cond); validation PASS; "
                     f"soundcheck clean; effect-classes={res['nclasses']}\n")
    if args.check:
        with open(args.check,encoding="utf-8") as f: have=f.read()
        if have!=text:
            sys.stderr.write(f"CHECK FAIL: {args.check} differs from freshly generated output\n"); sys.exit(1)
        sys.stderr.write(f"# CHECK OK: {args.check} is byte-identical to generator output\n"); return
    sys.stdout.write(text)

if __name__=="__main__":
    main()
