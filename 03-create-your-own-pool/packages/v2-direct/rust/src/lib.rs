//! Strict SKS2 (128-byte) and SDA2 (552-byte) codecs + SHA-256 public-input limbs.
//! Independent of the TypeScript implementation for cross-language KATs.

use sha2::{Digest, Sha256};

pub const POOL_STATE_BYTES: usize = 128;
pub const ACTION_PACKET_BYTES: usize = 552;
pub const STATE_MAGIC: &[u8; 4] = b"SKS2";
pub const PACKET_MAGIC: &[u8; 4] = b"SDA2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError(pub String);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CodecError {}

fn err(msg: impl Into<String>) -> CodecError {
    CodecError(msg.into())
}

/// Split SHA-256 digest into two 128-bit big-endian limbs (decimal strings).
pub fn sha256_digest_limbs(digest: &[u8; 32]) -> (String, String) {
    let hi = u128::from_be_bytes(digest[0..16].try_into().unwrap());
    let lo = u128::from_be_bytes(digest[16..32].try_into().unwrap());
    (hi.to_string(), lo.to_string())
}

pub fn digest_packet(packet: &[u8]) -> Result<([u8; 32], (String, String)), CodecError> {
    if packet.len() != ACTION_PACKET_BYTES {
        return Err(err(format!(
            "action packet must contain exactly {ACTION_PACKET_BYTES} bytes"
        )));
    }
    if &packet[0..4] != PACKET_MAGIC {
        return Err(err("action packet magic is invalid (expected SDA2)"));
    }
    let flags = u16::from_le_bytes([packet[6], packet[7]]);
    if flags != 0 {
        return Err(err("action packet flags must be zero"));
    }
    // State slices must be exact SKS2
    validate_state(&packet[40..168])?;
    validate_state(&packet[168..296])?;
    let mut hasher = Sha256::new();
    hasher.update(packet);
    let digest: [u8; 32] = hasher.finalize().into();
    let limbs = sha256_digest_limbs(&digest);
    Ok((digest, limbs))
}

pub fn validate_state(state: &[u8]) -> Result<(), CodecError> {
    if state.len() != POOL_STATE_BYTES {
        return Err(err(format!(
            "pool state must contain exactly {POOL_STATE_BYTES} bytes"
        )));
    }
    if &state[0..4] != STATE_MAGIC {
        return Err(err("pool state magic is invalid (expected SKS2)"));
    }
    Ok(())
}

pub fn encode_minimal_state(
    profile_id: &[u8; 32],
    note_root: &[u8; 32],
    nullifier_root: &[u8; 32],
    note_count: u32,
    nullifier_count: u32,
    maximum_live_notes: u32,
    reserve_sats: u64,
    action_sequence: u64,
) -> [u8; POOL_STATE_BYTES] {
    let mut out = [0u8; POOL_STATE_BYTES];
    out[0..4].copy_from_slice(STATE_MAGIC);
    out[4..36].copy_from_slice(profile_id);
    out[36..68].copy_from_slice(note_root);
    out[68..100].copy_from_slice(nullifier_root);
    out[100..104].copy_from_slice(&note_count.to_le_bytes());
    out[104..108].copy_from_slice(&nullifier_count.to_le_bytes());
    out[108..112].copy_from_slice(&maximum_live_notes.to_le_bytes());
    out[112..120].copy_from_slice(&reserve_sats.to_le_bytes());
    out[120..128].copy_from_slice(&action_sequence.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_state_len() {
        assert!(validate_state(&[0u8; 127]).is_err());
        assert!(validate_state(&[0u8; 129]).is_err());
    }

    #[test]
    fn limbs_split_known_digest() {
        let mut d = [0u8; 32];
        d[15] = 1;
        d[31] = 2;
        let (hi, lo) = sha256_digest_limbs(&d);
        assert_eq!(hi, "1");
        assert_eq!(lo, "2");
    }
}
