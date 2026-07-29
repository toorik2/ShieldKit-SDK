//! Cross-language KAT CLI: read packet hex on stdin or --packet-hex, print digest + limbs JSON.
use std::env;
use std::io::{self, Read};

use shieldkit_v2_direct::digest_packet;

fn main() {
    let mut packet_hex = String::new();
    let args: Vec<String> = env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--packet-hex") {
        packet_hex = args.get(i + 1).cloned().unwrap_or_default();
    } else {
        io::stdin().read_to_string(&mut packet_hex).expect("stdin");
    }
    let packet_hex = packet_hex.trim();
    let bytes = hex::decode(packet_hex).expect("hex decode");
    match digest_packet(&bytes) {
        Ok((digest, (hi, lo))) => {
            let out = serde_json::json!({
                "digest": hex::encode(digest),
                "publicInputs": [hi, lo],
            });
            println!("{out}");
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
