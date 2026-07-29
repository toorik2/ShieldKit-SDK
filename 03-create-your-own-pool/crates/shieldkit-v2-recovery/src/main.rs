#![forbid(unsafe_code)]

use shieldkit_v2_recovery::{
    AuthenticateSnapshotRequest, ScanRequest, VerifySnapshotRequest, authenticate_snapshot,
    scan_with_material,
    stream::{authenticate_snapshot_framed, scan_framed},
    verify_snapshot,
};
use std::io::{self, Read};

const MAX_REQUEST_BYTES: u64 = 256 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("shieldkit-v2-recovery: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    let command = arguments
        .next()
        .ok_or(
            "expected exactly one command: scan, scan-stream, authenticate-snapshot, authenticate-snapshot-stream, or verify-snapshot",
        )?;
    if arguments.next().is_some() {
        return Err(
            "expected exactly one command: scan, scan-stream, authenticate-snapshot, authenticate-snapshot-stream, or verify-snapshot"
                .into(),
        );
    }
    if command == "scan-stream" {
        return scan_framed(io::stdin().lock(), io::stdout().lock()).map_err(|error| error.into());
    }
    if command == "authenticate-snapshot-stream" {
        return authenticate_snapshot_framed(io::stdin().lock(), io::stdout().lock())
            .map_err(|error| error.into());
    }
    let mut input = Vec::new();
    io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut input)?;
    if input.len() as u64 > MAX_REQUEST_BYTES {
        return Err("JSON request exceeds 256 MiB".into());
    }
    let output = match command.as_str() {
        "scan" => {
            let request: ScanRequest = serde_json::from_slice(&input)?;
            serde_json::to_vec(&scan_with_material(&request)?)?
        }
        "authenticate-snapshot" => {
            let request: AuthenticateSnapshotRequest = serde_json::from_slice(&input)?;
            serde_json::to_vec(&authenticate_snapshot(&request)?)?
        }
        "verify-snapshot" => {
            let request: VerifySnapshotRequest = serde_json::from_slice(&input)?;
            serde_json::to_vec(&verify_snapshot(&request)?)?
        }
        _ => {
            return Err(
                "unsupported command; expected scan, scan-stream, authenticate-snapshot, authenticate-snapshot-stream, or verify-snapshot"
                    .into(),
            );
        }
    };
    println!("{}", String::from_utf8(output)?);
    Ok(())
}
