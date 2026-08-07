//! GF(p^2) = F_p[u]/(u^2 - 7)
use crate::field::{self, P};

pub const W: u64 = 7;
pub type Ext = (u64, u64);

pub const ZERO: Ext = (0, 0);
pub const ONE: Ext = (1, 0);
pub const U: Ext = (0, 1);

#[inline]
pub fn from_base(a: u64) -> Ext {
    (a % P, 0)
}

#[inline]
pub fn eq(a: Ext, b: Ext) -> bool {
    a.0 % P == b.0 % P && a.1 % P == b.1 % P
}

#[inline]
pub fn add(a: Ext, b: Ext) -> Ext {
    (field::add(a.0, b.0), field::add(a.1, b.1))
}

#[inline]
pub fn sub(a: Ext, b: Ext) -> Ext {
    (field::sub(a.0, b.0), field::sub(a.1, b.1))
}

#[inline]
pub fn mul(a: Ext, b: Ext) -> Ext {
    let a0 = a.0 % P;
    let a1 = a.1 % P;
    let b0 = b.0 % P;
    let b1 = b.1 % P;
    let t0 = field::mul(a0, b0);
    let t1 = field::mul(a1, b1);
    let t2 = field::mul(field::add(a0, a1), field::add(b0, b1));
    let c0 = field::add(t0, field::mul(W, t1));
    let c1 = field::sub(t2, field::add(t0, t1));
    (c0, c1)
}

#[inline]
pub fn scalar(s: u64, a: Ext) -> Ext {
    let s = s % P;
    (field::mul(s, a.0), field::mul(s, a.1))
}

#[inline]
pub fn conj(a: Ext) -> Ext {
    (a.0 % P, field::neg(a.1))
}

#[inline]
pub fn norm(a: Ext) -> u64 {
    field::sub(field::mul(a.0, a.0), field::mul(W, field::mul(a.1, a.1)))
}

#[inline]
pub fn inv(a: Ext) -> Ext {
    let n = norm(a);
    assert!(n != 0, "GF(p^2) inverse of zero");
    let ninv = field::inv(n);
    (field::mul(a.0, ninv), field::mul(field::neg(a.1), ninv))
}

pub fn power(mut a: Ext, mut e: u64) -> Ext {
    let mut result = ONE;
    while e > 0 {
        if e & 1 == 1 {
            result = mul(result, a);
        }
        a = mul(a, a);
        e >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonresidue() {
        // Euler: W^((p-1)/2) == p-1
        assert_eq!(field::mod_pow(W, (P - 1) / 2), P - 1);
    }
    #[test]
    fn u_sq() {
        assert!(eq(mul(U, U), from_base(W)));
    }
}
