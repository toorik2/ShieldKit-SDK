use crate::field::{self, P};
use rayon::prelude::*;

fn bit_reverse(a: &mut [u64]) {
    let n = a.len();
    let logn = n.trailing_zeros();
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS - logn);
        if i < j {
            a.swap(i, j);
        }
    }
}

fn ntt_inplace(a: &mut [u64], omega: u64) {
    let n = a.len();
    bit_reverse(a);
    let mut m = 2usize;
    while m <= n {
        let wm = field::mod_pow(omega, (n / m) as u64);
        for s in (0..n).step_by(m) {
            let mut w = 1u64;
            let half = m / 2;
            for k in 0..half {
                let t = field::mul(w, a[s + k + half]);
                let u = a[s + k];
                a[s + k] = field::add(u, t);
                a[s + k + half] = field::sub(u, t);
                w = field::mul(w, wm);
            }
        }
        m <<= 1;
    }
}

pub fn ntt(coeffs: &[u64], omega: u64) -> Vec<u64> {
    let mut a = coeffs.to_vec();
    ntt_inplace(&mut a, omega);
    a
}

pub fn intt(values: &[u64], omega: u64) -> Vec<u64> {
    let n = values.len();
    let mut a = values.to_vec();
    ntt_inplace(&mut a, field::inv(omega));
    let ninv = field::inv(n as u64);
    for v in a.iter_mut() {
        *v = field::mul(*v, ninv);
    }
    a
}

/// LDE onto coset offset * <oN>
pub fn lde_coset(
    h_vals: &[u64],
    t: usize,
    n: usize,
    ot: u64,
    on: u64,
    offset: u64,
    mask_r: Option<&[u64]>,
) -> Vec<u64> {
    let mut coeffs = intt(h_vals, ot);
    coeffs.resize(n, 0);
    if let Some(mask_r) = mask_r {
        let m = mask_r.len();
        assert!(t + m <= n);
        for k in 0..m {
            coeffs[k] = field::sub(coeffs[k], mask_r[k]);
            coeffs[t + k] = field::add(coeffs[t + k], mask_r[k]);
        }
    }
    let mut scaled = vec![0u64; n];
    let mut o = 1u64;
    for k in 0..n {
        scaled[k] = field::mul(coeffs[k], o);
        o = field::mul(o, offset);
    }
    ntt(&scaled, on)
}

/// Parallel LDE of many columns (same domain).
/// Cap concurrency: each LDE holds ~3·N field elements of temporaries; unbounded
/// rayon over 52 columns at N≈4e6 blows past the 4 GiB SLA peak.
pub fn lde_coset_batch(
    columns: &[Vec<u64>],
    t: usize,
    n: usize,
    ot: u64,
    on: u64,
    offset: u64,
    masks: &[Vec<u64>],
) -> Vec<Vec<u64>> {
    // ~3 GiB budget for temps: 3 * n * 8 * threads ≲ 2.5e9 → threads ≲ 2.5e9/(24n)
    let max_threads = if n >= 1 << 20 {
        2usize.max(4.min(std::thread::available_parallelism().map(|p| p.get()).unwrap_or(4) / 2))
    } else {
        std::thread::available_parallelism().map(|p| p.get()).unwrap_or(4)
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(max_threads)
        .build()
        .expect("rayon LDE pool");
    pool.install(|| {
        columns
            .par_iter()
            .zip(masks.par_iter())
            .map(|(h, m)| lde_coset(h, t, n, ot, on, offset, Some(m.as_slice())))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{mod_pow, root};
    #[test]
    fn roundtrip() {
        for n in [2usize, 8, 64] {
            let omega = root(n as u64);
            let coeffs: Vec<u64> = (0..n as u64).map(|i| i * 7 + 3).collect();
            let vals = ntt(&coeffs, omega);
            let back = intt(&vals, omega);
            assert_eq!(back, coeffs);
            for i in 0..n {
                let x = mod_pow(omega, i as u64);
                let mut acc = 0u64;
                for &c in coeffs.iter().rev() {
                    acc = field::add(field::mul(acc, x), c);
                }
                assert_eq!(vals[i], acc);
            }
        }
    }
}
