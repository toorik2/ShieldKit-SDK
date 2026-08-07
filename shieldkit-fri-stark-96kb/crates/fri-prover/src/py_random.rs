//! CPython 3 `random.Random` MT19937 (enough for `randrange(1, P)` witness parity).
//! Seed path matches `Random(int_seed)` → `init_by_array` of 32-bit limbs (little-endian).

const N: usize = 624;
const M: usize = 397;
const MATRIX_A: u32 = 0x9908b0df;
const UPPER_MASK: u32 = 0x80000000;
const LOWER_MASK: u32 = 0x7fffffff;

pub struct PyRandom {
    mt: [u32; N],
    mti: usize,
}

impl PyRandom {
    pub fn new(seed: u64) -> Self {
        let mut r = Self {
            mt: [0; N],
            mti: N + 1,
        };
        r.seed_u64(seed);
        r
    }

    fn seed_u64(&mut self, seed: u64) {
        // CPython: for int seeds, pack absolute value as little-endian 32-bit words.
        let mut key = Vec::new();
        if seed == 0 {
            key.push(0u32);
        } else {
            let mut x = seed;
            while x > 0 {
                key.push((x & 0xffff_ffff) as u32);
                x >>= 32;
            }
        }
        self.init_by_array(&key);
    }

    fn init_genrand(&mut self, s: u32) {
        self.mt[0] = s;
        for i in 1..N {
            self.mt[i] = 1812433253u32
                .wrapping_mul(self.mt[i - 1] ^ (self.mt[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        self.mti = N;
    }

    fn init_by_array(&mut self, key: &[u32]) {
        self.init_genrand(19650218);
        let mut i = 1usize;
        let mut j = 0usize;
        let mut k = N.max(key.len());
        while k > 0 {
            self.mt[i] = (self.mt[i]
                ^ ((self.mt[i - 1] ^ (self.mt[i - 1] >> 30)).wrapping_mul(1664525)))
            .wrapping_add(key[j])
            .wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= N {
                self.mt[0] = self.mt[N - 1];
                i = 1;
            }
            if j >= key.len() {
                j = 0;
            }
            k -= 1;
        }
        k = N - 1;
        while k > 0 {
            self.mt[i] = (self.mt[i]
                ^ ((self.mt[i - 1] ^ (self.mt[i - 1] >> 30)).wrapping_mul(1566083941)))
            .wrapping_sub(i as u32);
            i += 1;
            if i >= N {
                self.mt[0] = self.mt[N - 1];
                i = 1;
            }
            k -= 1;
        }
        self.mt[0] = 0x80000000;
    }

    fn genrand_uint32(&mut self) -> u32 {
        let mag01 = [0u32, MATRIX_A];
        if self.mti >= N {
            for kk in 0..(N - M) {
                let y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk + 1] & LOWER_MASK);
                self.mt[kk] = self.mt[kk + M] ^ (y >> 1) ^ mag01[(y & 1) as usize];
            }
            for kk in (N - M)..(N - 1) {
                let y = (self.mt[kk] & UPPER_MASK) | (self.mt[kk + 1] & LOWER_MASK);
                self.mt[kk] = self.mt[kk + M - N] ^ (y >> 1) ^ mag01[(y & 1) as usize];
            }
            let y = (self.mt[N - 1] & UPPER_MASK) | (self.mt[0] & LOWER_MASK);
            self.mt[N - 1] = self.mt[M - 1] ^ (y >> 1) ^ mag01[(y & 1) as usize];
            self.mti = 0;
        }
        let mut y = self.mt[self.mti];
        self.mti += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >> 18;
        y
    }

    /// CPython `getrandbits(64)` (two 32-bit words, low then high).
    pub fn getrandbits64(&mut self) -> u64 {
        let lo = self.genrand_uint32() as u64;
        let hi = self.genrand_uint32() as u64;
        lo | (hi << 32)
    }

    /// `randrange(1, p)` for Goldilocks modulus p = 2^64-2^32+1.
    pub fn randrange_1_p(&mut self, p: u64) -> u64 {
        // width of (p-1) is 64 bits → rejection on getrandbits(64)
        let n = p - 1; // values in 0..n-1 then +1 → 1..p-1
        loop {
            let r = self.getrandbits64();
            if r < n {
                return r + 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_cpython_seed1() {
        let mut r = PyRandom::new(1);
        let expect = [
            10499958131665514998u64,
            14799178230035213024,
            1164115433906158533,
            2175216119781798973,
            14037279428536751484,
        ];
        for e in expect {
            assert_eq!(r.randrange_1_p(0xFFFF_FFFF_0000_0001), e);
        }
    }
}
