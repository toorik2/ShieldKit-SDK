//! Length-prefixed / line-oriented JSON worker: manifest | prove | verify | fri-terms | assemble-unlocks
//! Product prove + FRI unlock materialization is native Rust (shieldkit-fri-prover).
use serde_json::{json, Value};
use shieldkit_fri_prover::{
    assemble_unlocks_from_proof, prove, prove_kind, query_fri_terms_fold8, stitch_redeems_unlocks,
    verify_proof, FriParams, RedeemIn, Witness,
};
use std::io::{self, Read, Write};
use std::time::Instant;

const SFS1_LEN: usize = 128;
const SFP1_LEN: usize = 424;

fn main() {
    let mut stdin = io::stdin();
    let mut buf = Vec::new();
    let _ = stdin.read_to_end(&mut buf);
    let req = String::from_utf8_lossy(&buf);
    let line = req.lines().next().unwrap_or("").trim();
    if line.is_empty() || line == "manifest" || line.contains("\"cmd\":\"manifest\"") {
        println!("{}", manifest());
        return;
    }
    if let Ok(v) = serde_json::from_str::<Value>(line) {
        match v.get("cmd").and_then(|c| c.as_str()).unwrap_or("") {
            "manifest" => {
                println!("{}", manifest());
                return;
            }
            "prove" => {
                let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("deposit");
                let depth = v.get("depth").and_then(|x| x.as_u64()).unwrap_or(32) as usize;
                // Production default: RANDOM ZK mask (CSPRNG). An explicit "seed" is the
                // test/oracle path only (deterministic masks). randomMask:false + seed
                // also forces the deterministic path for corpus reproducibility.
                let random_mask = v.get("randomMask").and_then(|x| x.as_bool()).unwrap_or(true);
                let seed = if random_mask { None } else { v.get("seed").and_then(|x| x.as_u64()) };
                let mut params = FriParams::default();
                if let Some(b) = v.get("blowup").and_then(|x| x.as_u64()) {
                    params.blowup = b;
                }
                if let Some(q) = v.get("queries").and_then(|x| x.as_u64()) {
                    params.queries = q as usize;
                }
                if let Some(g) = v.get("grindBits").and_then(|x| x.as_u64()) {
                    params.grind_bits = g as u32;
                }
                if let Some(f) = v.get("foldStep").and_then(|x| x.as_u64()) {
                    params.fold_step = f as usize;
                }
                if let Some(m) = v.get("maskDeg").and_then(|x| x.as_u64()) {
                    params.mask_deg = m as usize;
                }
                if let Some(d) = v.get("deep").and_then(|x| x.as_bool()) {
                    params.deep = d;
                }
                // development selftest shortcut
                if v.get("eligibility").and_then(|x| x.as_str()) == Some("development-only") {
                    params.blowup = 4;
                    params.queries = 2;
                    params.grind_bits = 2;
                    params.fold_step = 1;
                    params.mask_deg = 8;
                    params.deep = true;
                }
                let t0 = Instant::now();
                let r = if let Some(wv) = v.get("witness") {
                    // PRODUCTION path (item 2): the caller (wallet) supplies the full
                    // witness — note secrets derived from wallet key material, never
                    // from a seed. Mask randomness is governed by `seed`/`randomMask`.
                    // JSON numbers lose u64 precision in JS (float64), so the wire format
                    // uses DECIMAL STRINGS for every field (the wallet emits exact BigInt strings).
                    #[derive(serde::Deserialize)]
                    struct WitnessIn {
                        sk: String, rho_in: String, blind_in: String,
                        value_in: String, fee: String,
                        value_outs: [String; 2], owners_out: [String; 2],
                        rhos_out: [String; 2], blinds_out: [String; 2],
                        siblings: Vec<String>,
                    }
                    fn p64(x: &str) -> u64 { x.trim().parse::<u64>().unwrap_or(0) }
                    match serde_json::from_value::<WitnessIn>(wv.clone()) {
                        Ok(wi) => {
                            let w = Witness {
                                sk: p64(&wi.sk), rho_in: p64(&wi.rho_in), blind_in: p64(&wi.blind_in),
                                value_in: p64(&wi.value_in), fee: p64(&wi.fee),
                                value_outs: [p64(&wi.value_outs[0]), p64(&wi.value_outs[1])],
                                owners_out: [p64(&wi.owners_out[0]), p64(&wi.owners_out[1])],
                                rhos_out: [p64(&wi.rhos_out[0]), p64(&wi.rhos_out[1])],
                                blinds_out: [p64(&wi.blinds_out[0]), p64(&wi.blinds_out[1])],
                                siblings: wi.siblings.iter().map(|x| p64(x)).collect(),
                            };
                            let d = w.siblings.len();
                            let mut rr = shieldkit_fri_prover::prove(&w, &params, seed, kind);
                            rr.depth = d;
                            rr.mask_seed = seed;
                            rr.witness_seed = u64::MAX; // caller-supplied witness (not seed-derived)
                            rr.mask_source = Some(match seed {
                                Some(_) => "splitmix64(seed)".to_string(),
                                None => "csprng(thread_rng, 128-bit)".to_string(),
                            });
                            rr
                        }
                        Err(e) => {
                            println!("{}", json!({"ok": false, "error": format!("witness parse: {e}")}));
                            return;
                        }
                    }
                } else {
                    prove_kind(kind, depth, &params, seed)
                };
                // Optional full proof dump for product assemble (path or "1" → stdout-adjacent file).
                if let Some(pout) = v.get("proofOut").and_then(|x| x.as_str()) {
                    let path = if pout == "1" || pout.is_empty() {
                        format!(
                            "/tmp/grok-goal-a75a99dfd55d/implementer/pf-cache/pf-{}-d{}-b{}-n{}-g{}-s{}.json",
                            kind, depth, params.blowup, params.queries, params.grind_bits,
                            seed.map(|s| s.to_string()).unwrap_or_else(|| "r".to_string())
                        )
                    } else {
                        pout.to_string()
                    };
                    if let Some(parent) = std::path::Path::new(&path).parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    // JS consumers cannot represent u64 JSON numbers exactly (float64),
                    // so the proof dump serializes every number as a DECIMAL STRING.
                    // Python consumers convert the strings back to ints at pickle time.
                    if let Ok(v) = serde_json::to_value(&r.proof) {
                        fn num_to_str(v: serde_json::Value) -> serde_json::Value {
                            match v {
                                serde_json::Value::Number(n) => serde_json::Value::String(n.to_string()),
                                serde_json::Value::Array(a) => serde_json::Value::Array(a.into_iter().map(num_to_str).collect()),
                                serde_json::Value::Object(o) => serde_json::Value::Object(
                                    o.into_iter().map(|(k, v)| (k, num_to_str(v))).collect()),
                                other => other,
                            }
                        }
                        let s = serde_json::to_vec(&num_to_str(v)).unwrap_or_default();
                        let _ = std::fs::write(&path, s);
                    }
                }
                // Emit u64 statement limbs as decimal strings (JS JSON number is not u64-safe).
                let out = json!({
                    "ok": r.verify_ok,
                    "verifyOk": r.verify_ok,
                    "kind": kind,
                    "depth": depth,
                    "proveSeconds": r.prove_seconds,
                    "peakRssBytes": r.peak_rss_bytes,
                    "proofBlobSha256": r.proof_blob_sha256,
                    "maskSource": r.mask_source,
                    "maskSeed": r.mask_seed,
                    "witnessSeed": r.witness_seed,
                    "statement": {
                        "root": r.statement.root.to_string(),
                        "nf": r.statement.nf.to_string(),
                        "cm_out": [
                            r.statement.cm_out[0].to_string(),
                            r.statement.cm_out[1].to_string(),
                        ],
                        "depth": r.statement.depth,
                        "kind": r.statement.kind,
                    },
                    "engine": r.engine,
                    "wallSeconds": t0.elapsed().as_secs_f64(),
                    "usesPython": false,
                });
                println!("{}", out);
                if !r.verify_ok {
                    std::process::exit(1);
                }
                return;
            }
            "verify" => {
                let ok = match v.get("proof") {
                    Some(p) => verify_proof(p),
                    None => false,
                };
                println!(
                    "{{\"ok\":{},\"engine\":\"shieldkit-fri-prover-rust\",\"verifyMode\":\"deep-ali-fri\"}}",
                    ok
                );
                if !ok {
                    std::process::exit(1);
                }
                return;
            }
            "verify-state" => {
                let hex = v.get("hex").and_then(|x| x.as_str()).unwrap_or("");
                let ok = hex.len() == SFS1_LEN * 2 && hex.starts_with("53465331");
                println!("{{\"ok\":{},\"len\":{}}}", ok, hex.len() / 2);
                return;
            }
            "verify-packet" => {
                let hex = v.get("hex").and_then(|x| x.as_str()).unwrap_or("");
                let ok = hex.len() == SFP1_LEN * 2 && hex.starts_with("53465031");
                println!("{{\"ok\":{},\"len\":{}}}", ok, hex.len() / 2);
                return;
            }
            // Fast FRI terms from proof dump (replaces pure-Python query_fri_terms_fold8).
            "fri-terms" => {
                let t0 = Instant::now();
                match load_proof_arg(&v).and_then(|p| query_fri_terms_fold8(&p)) {
                    Ok(terms) => {
                        let out = json!({
                            "ok": true,
                            "engine": "shieldkit-fri-prover-rust",
                            "nQueries": terms.len(),
                            "queries": terms,
                            "wallSeconds": t0.elapsed().as_secs_f64(),
                        });
                        println!("{}", out);
                    }
                    Err(e) => {
                        println!("{}", json!({"ok": false, "error": e}));
                        std::process::exit(1);
                    }
                }
                return;
            }
            // Materialize FRI unlock packs from proof dump; optional redeem stitch.
            "assemble-unlocks" => {
                let proof = match load_proof_arg(&v) {
                    Ok(p) => p,
                    Err(e) => {
                        println!("{}", json!({"ok": false, "error": e}));
                        std::process::exit(1);
                    }
                };
                let pad = v.get("aggfriPad").and_then(|x| x.as_u64()).unwrap_or(120) as usize;
                match assemble_unlocks_from_proof(&proof, pad) {
                    Ok(mut res) => {
                        if let Some(rp) = v.get("redeemsPath").and_then(|x| x.as_str()) {
                            if let Ok(bytes) = std::fs::read(rp) {
                                if let Ok(redeems) = serde_json::from_slice::<Vec<RedeemIn>>(&bytes) {
                                    // Map aggFRI unlocks onto role indices if provided via redeems.
                                    // Map aggFRI unlocks onto redeems with role aggFRI (order).
                                    let mut ag_i = 0usize;
                                    let mut ov = Vec::new();
                                    for r in &redeems {
                                        if r.role == "aggFRI" && ag_i < res.aggfri_unlocks.len() {
                                            ov.push((
                                                r.index,
                                                res.aggfri_unlocks[ag_i].unlock_bytecode_hex.clone(),
                                            ));
                                            ag_i += 1;
                                        }
                                    }
                                    let stitched = stitch_redeems_unlocks(&redeems, &ov);
                                    let out_path = v
                                        .get("out")
                                        .and_then(|x| x.as_str())
                                        .map(|s| s.to_string());
                                    let payload = json!({
                                        "ok": true,
                                        "engine": res.engine,
                                        "wallSeconds": res.wall_seconds,
                                        "nQueries": res.n_queries,
                                        "aggfriUnlocks": res.aggfri_unlocks,
                                        "stitched": stitched,
                                        "note": res.note,
                                    });
                                    if let Some(p) = out_path {
                                        if let Some(parent) = std::path::Path::new(&p).parent() {
                                            let _ = std::fs::create_dir_all(parent);
                                        }
                                        let _ = std::fs::write(&p, serde_json::to_vec_pretty(&payload).unwrap_or_default());
                                    }
                                    println!("{}", payload);
                                    return;
                                }
                            }
                        }
                        let out_path = v.get("out").and_then(|x| x.as_str());
                        if let Some(p) = out_path {
                            if let Some(parent) = std::path::Path::new(p).parent() {
                                let _ = std::fs::create_dir_all(parent);
                            }
                            let _ = std::fs::write(
                                p,
                                serde_json::to_vec_pretty(&res).unwrap_or_default(),
                            );
                        }
                        println!("{}", serde_json::to_string(&res).unwrap_or_else(|_| "{}".into()));
                    }
                    Err(e) => {
                        println!("{}", json!({"ok": false, "error": e}));
                        std::process::exit(1);
                    }
                }
                return;
            }
            _ => {}
        }
    }
    // legacy text commands
    if line.contains("verify-state") {
        let hex = line.split_whitespace().nth(1).unwrap_or("");
        let ok = hex.len() == SFS1_LEN * 2 && hex.starts_with("53465331");
        println!("{{\"ok\":{},\"len\":{}}}", ok, hex.len() / 2);
        return;
    }
    if line.contains("verify-packet") {
        let hex = line.split_whitespace().nth(1).unwrap_or("");
        let ok = hex.len() == SFP1_LEN * 2 && hex.starts_with("53465031");
        println!("{{\"ok\":{},\"len\":{}}}", ok, hex.len() / 2);
        return;
    }
    eprintln!("unknown request: {line}");
    std::process::exit(2);
}

fn load_proof_arg(v: &Value) -> Result<Value, String> {
    if let Some(p) = v.get("proofPath").and_then(|x| x.as_str()) {
        let bytes = std::fs::read(p).map_err(|e| format!("read proofPath: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("parse proof JSON: {e}"))
    } else if let Some(p) = v.get("proof") {
        Ok(p.clone())
    } else {
        Err("assemble/fri-terms requires proofPath or proof".into())
    }
}

fn manifest() -> String {
    serde_json::json!({
        "schema": "shieldkit-fri-worker-manifest-v2",
        "relationId": "shieldkit-pool-action-fri-v1",
        "sfs1": SFS1_LEN,
        "sfp1": SFP1_LEN,
        "cmds": ["manifest", "prove", "verify", "fri-terms", "assemble-unlocks"],
        "topologyId": "fri-sound-lean-fused-state0-v1",
        "version": "0.1.0-beta.1",
        "engine": "shieldkit-fri-prover-rust",
        "usesPython": false,
    })
    .to_string()
}
