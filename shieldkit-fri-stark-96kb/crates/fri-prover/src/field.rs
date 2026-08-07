//! Goldilocks field p = 2^64 - 2^32 + 1
pub const P: u64 = 0xFFFF_FFFF_0000_0001; // 2^64 - 2^32 + 1

#[inline]
pub fn add(a: u64, b: u64) -> u64 {
    let (s, c) = a.overflowing_add(b);
    if c || s >= P {
        s.wrapping_sub(P)
    } else {
        s
    }
}

#[inline]
pub fn sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        a.wrapping_add(P - b)
    }
}

#[inline]
pub fn neg(a: u64) -> u64 {
    if a == 0 {
        0
    } else {
        P - a
    }
}

#[inline]
pub fn mul(a: u64, b: u64) -> u64 {
    let wide = (a as u128) * (b as u128);
    // reduction mod Goldilocks (Plonky2-style style simple reduce)
    (wide % (P as u128)) as u64
}

#[inline]
pub fn inv(a: u64) -> u64 {
    // Fermat: a^(p-2) mod p
    mod_pow(a % P, P - 2)
}

#[inline]
pub fn mod_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut res = 1u64;
    base %= P;
    while exp > 0 {
        if exp & 1 == 1 {
            res = mul(res, base);
        }
        base = mul(base, base);
        exp >>= 1;
    }
    res
}

/// Multiplicative generator G of Goldilocks (same search as stark.py find_gen).
pub fn find_gen() -> u64 {
    let factors: [u64; 6] = [2, 3, 5, 17, 257, 65537];
    for g in 2u64..200 {
        if factors.iter().all(|&f| mod_pow(g, (P - 1) / f) != 1) {
            return g;
        }
    }
    panic!("no generator");
}

pub fn root(order: u64) -> u64 {
    assert!((P - 1) % order == 0);
    mod_pow(find_gen(), (P - 1) / order)
}

pub fn enc(v: u64) -> [u8; 8] {
    (v % P).to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn field_inv() {
        for a in [1u64, 2, 7, 12345, P - 1] {
            assert_eq!(mul(a, inv(a)), 1);
        }
    }
    #[test]
    fn gen_matches_python() {
        // stark.py find_gen returns 7 for Goldilocks
        assert_eq!(find_gen(), 7);
    }
}
