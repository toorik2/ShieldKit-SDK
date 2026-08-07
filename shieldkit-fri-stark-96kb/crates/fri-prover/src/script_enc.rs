//! Minimal BCH script push encoding for unlock materialization.
use crate::field;

/// Encode a minimal Script number (Bitcoin/BCH consensus).
pub fn encode_num(mut n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let mut abs = n as u64;
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if out.last().map(|b| b & 0x80).unwrap_or(0) != 0 {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        let i = out.len() - 1;
        out[i] |= 0x80;
    }
    out
}

/// OP_PUSHDATA for arbitrary bytes.
pub fn encode_data_push(data: &[u8]) -> Vec<u8> {
    let n = data.len();
    let mut out = Vec::with_capacity(n + 5);
    if n < 0x4c {
        out.push(n as u8);
    } else if n <= 0xff {
        out.push(0x4c);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0x4d);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(0x4e);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
    out
}

pub fn push_num(n: u64) -> Vec<u8> {
    let v = (n % field::P) as i64;
    // Bitcoin minimal encoding for small ints uses OP_1..OP_16 when possible — keep byte push for field elems.
    encode_data_push(&encode_num(v))
}

pub fn push_bytes(data: &[u8]) -> Vec<u8> {
    encode_data_push(data)
}

pub fn enc8(v: u64) -> [u8; 8] {
    field::enc(v)
}

/// Concatenate script fragments.
pub fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_small() {
        let p = encode_data_push(&[1, 2, 3]);
        assert_eq!(p[0], 3);
        assert_eq!(&p[1..], &[1, 2, 3]);
    }
}
