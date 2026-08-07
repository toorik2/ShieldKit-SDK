//! Poseidon2 t=12 over Goldilocks (HorizenLabs KAT)
use crate::field::{self, P};
use crate::poseidon2_constants::{MAT_DIAG12, RC, ROUNDS_F, ROUNDS_P};
pub use crate::poseidon2_constants::WIDTH;
pub const RATE: usize = 8;


const RF_HALF: usize = ROUNDS_F / 2;
const ROUNDS: usize = ROUNDS_F + ROUNDS_P;
#[inline]
fn sbox_p(x: u64) -> u64 {
    let x2 = field::mul(x, x);
    let x4 = field::mul(x2, x2);
    let x6 = field::mul(x4, x2);
    field::mul(x6, x)
}

fn matmul_m4(s: &mut [u64; WIDTH]) {
    for i in (0..WIDTH).step_by(4) {
        let t0 = field::add(s[i], s[i + 1]);
        let t1 = field::add(s[i + 2], s[i + 3]);
        let t2 = field::add(field::mul(2, s[i + 1]), t1);
        let t3 = field::add(field::mul(2, s[i + 3]), t0);
        let t4 = field::add(field::mul(4, t1), t3);
        let t5 = field::add(field::mul(4, t0), t2);
        let t6 = field::add(t3, t5);
        let t7 = field::add(t2, t4);
        s[i] = t6;
        s[i + 1] = t5;
        s[i + 2] = t7;
        s[i + 3] = t4;
    }
}

fn matmul_external(s: &mut [u64; WIDTH]) {
    matmul_m4(s);
    let mut stored = [0u64; 4];
    let t4 = WIDTH / 4;
    for l in 0..4 {
        let mut acc = s[l];
        for j in 1..t4 {
            acc = field::add(acc, s[4 * j + l]);
        }
        stored[l] = acc;
    }
    for i in 0..WIDTH {
        s[i] = field::add(s[i], stored[i % 4]);
    }
}

fn matmul_internal(s: &mut [u64; WIDTH]) {
    let mut total = 0u64;
    for v in s.iter() {
        total = field::add(total, *v);
    }
    for i in 0..WIDTH {
        s[i] = field::add(field::mul(s[i], MAT_DIAG12[i]), total);
    }
}

pub fn permutation(state_in: &[u64; WIDTH]) -> [u64; WIDTH] {
    let mut s = *state_in;
    for v in s.iter_mut() {
        *v %= P;
    }
    matmul_external(&mut s);
    for r in 0..RF_HALF {
        for i in 0..WIDTH {
            s[i] = sbox_p(field::add(s[i], RC[r][i]));
        }
        matmul_external(&mut s);
    }
    let p_end = RF_HALF + ROUNDS_P;
    for r in RF_HALF..p_end {
        s[0] = sbox_p(field::add(s[0], RC[r][0]));
        matmul_internal(&mut s);
    }
    for r in p_end..ROUNDS {
        for i in 0..WIDTH {
            s[i] = sbox_p(field::add(s[i], RC[r][i]));
        }
        matmul_external(&mut s);
    }
    s
}

/// Round-per-row trace for AIR (states[0]=after initial external, states[30]=out)
pub fn permutation_trace(state_in: &[u64; WIDTH]) -> (Vec<[u64; WIDTH]>, Vec<RoundAux>) {
    let mut s = *state_in;
    for v in s.iter_mut() {
        *v %= P;
    }
    matmul_external(&mut s);
    let mut states = vec![s];
    let mut aux = Vec::with_capacity(ROUNDS);
    let p_end = RF_HALF + ROUNDS_P;
    for r in 0..ROUNDS {
        let cur = states[r];
        let full = r < RF_HALF || r >= p_end;
        let mut x2 = [0u64; WIDTH];
        let mut x4 = [0u64; WIDTH];
        let mut x6 = [0u64; WIDTH];
        let mut y = [0u64; WIDTH];
        let mut ns = cur;
        if full {
            for i in 0..WIDTH {
                let x = field::add(cur[i], RC[r][i]);
                let a = field::mul(x, x);
                let b = field::mul(a, a);
                let c = field::mul(b, a);
                x2[i] = a;
                x4[i] = b;
                x6[i] = c;
                y[i] = field::mul(c, x);
                ns[i] = y[i];
            }
            matmul_external(&mut ns);
        } else {
            let x = field::add(cur[0], RC[r][0]);
            let a = field::mul(x, x);
            let b = field::mul(a, a);
            let c = field::mul(b, a);
            x2[0] = a;
            x4[0] = b;
            x6[0] = c;
            y[0] = field::mul(c, x);
            for i in 1..WIDTH {
                y[i] = cur[i];
            }
            ns[0] = y[0];
            matmul_internal(&mut ns);
        }
        aux.push(RoundAux {
            full,
            x2,
            x4,
            x6,
            y,
        });
        states.push(ns);
    }
    (states, aux)
}

#[derive(Clone)]
pub struct RoundAux {
    pub full: bool,
    pub x2: [u64; WIDTH],
    pub x4: [u64; WIDTH],
    pub x6: [u64; WIDTH],
    pub y: [u64; WIDTH],
}

pub fn hash_to_1(inputs: &[u64]) -> u64 {
    let mut state = [0u64; WIDTH];
    let mut items: Vec<u64> = inputs.iter().map(|v| *v % P).collect();
    if items.is_empty() {
        items.push(0);
    }
    let pad = (RATE - items.len() % RATE) % RATE;
    items.extend(std::iter::repeat(0).take(pad));
    for off in (0..items.len()).step_by(RATE) {
        for i in 0..RATE {
            state[i] = field::add(state[i], items[off + i]);
        }
        state = permutation(&state);
    }
    state[0]
}

pub fn merkle_compress(a: u64, b: u64) -> u64 {
    hash_to_1(&[a, b])
}

#[cfg(test)]
mod tests {
    use super::*;
    const KAT_EXPECTED: [u64; 12] = [
        0x01eaef96bdf1c0c1,
        0x1f0d2cc525b2540c,
        0x6282c1dfe1e0358d,
        0xe780d721f698e1e6,
        0x280c0b6f753d833b,
        0x1b942dd5023156ab,
        0x43f0df3fcccb8398,
        0xe8e8190585489025,
        0x56bdbf72f77ada22,
        0x7911c32bf9dcd705,
        0xec467926508fbe67,
        0x6a50450ddf85a6ed,
    ];
    #[test]
    fn kat() {
        let inp: [u64; 12] = std::array::from_fn(|i| i as u64);
        assert_eq!(permutation(&inp), KAT_EXPECTED);
        let (st, _) = permutation_trace(&inp);
        assert_eq!(st[st.len() - 1], KAT_EXPECTED);
    }
}
