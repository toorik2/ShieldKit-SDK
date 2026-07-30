#![forbid(unsafe_code)]

use shieldkit_v2_recovery::q07_lifecycle::verify_q07_lifecycle;
use std::io::{self, BufReader};

fn main() {
    if let Err(error) = run() {
        eprintln!("q07-lifecycle-verify: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().count() != 1 {
        return Err("reads the Q07 non-chain corpus from stdin and accepts no arguments".into());
    }
    let result = verify_q07_lifecycle(BufReader::new(io::stdin().lock()))?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
