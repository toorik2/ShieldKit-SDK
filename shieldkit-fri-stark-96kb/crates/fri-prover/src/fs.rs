use crate::field::{enc, P};
use crate::merkle::sha256f;

pub struct Fs {
    pub s: Vec<u8>,
}

impl Fs {
    pub fn new() -> Self {
        Self {
            s: b"STARK-v0".to_vec(),
        }
    }
    pub fn absorb(&mut self, b: &[u8]) {
        let mut cat = self.s.clone();
        cat.extend_from_slice(b);
        self.s = sha256f(&cat).to_vec();
    }
    pub fn absorb_int(&mut self, v: u64) {
        self.absorb(&enc(v % P));
    }
    pub fn challenge(&mut self) -> u64 {
        let mut cat = self.s.clone();
        cat.extend_from_slice(b"chal");
        self.s = sha256f(&cat).to_vec();
        u64::from_le_bytes(self.s[..8].try_into().unwrap()) % P
    }
    pub fn challenge_idx(&mut self, n: usize) -> usize {
        let mut cat = self.s.clone();
        cat.extend_from_slice(b"idx");
        self.s = sha256f(&cat).to_vec();
        (u64::from_le_bytes(self.s[..8].try_into().unwrap()) as usize) % n
    }
}

pub fn grind(transcript_state: &[u8], bits: u32) -> [u8; 8] {
    let target = 1u64 << (64 - bits);
    // PRODUCT PATCH (2026-08-06): parallel PoW grind. The search is trivially parallel
    // (disjoint ranges per thread); the winning nonce still satisfies v < 2^(64-bits), so
    // soundness/verification is unchanged. Sequential fallback when parallelism is 1.
    // SLA: grind-30 went from ~70 s single-threaded to seconds on multi-core hosts.
    let threads = std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(1)
        .min(32);
    if threads <= 1 {
        return grind_seq(transcript_state, bits);
    }
    use std::sync::atomic::{AtomicU64, Ordering};
    let found = AtomicU64::new(u64::MAX);
    let found_ref = &found;
    let ts_ref = transcript_state;
    std::thread::scope(|scope| {
        for t in 0..threads {
            let found = found_ref;
            let ts = ts_ref;
            scope.spawn(move || {
                let mut i = t as u64;
                let mut buf = Vec::with_capacity(transcript_state.len() + 8);
                loop {
                    if found.load(Ordering::Relaxed) != u64::MAX {
                        return; // another thread won
                    }
                    buf.clear();
                    buf.extend_from_slice(ts);
                    buf.extend_from_slice(&i.to_le_bytes());
                    let h = sha256f(&buf);
                    let v = u64::from_le_bytes(h[..8].try_into().unwrap());
                    if v < target {
                        let _ = found.compare_exchange(u64::MAX, i, Ordering::Relaxed, Ordering::Relaxed);
                        return;
                    }
                    i += threads as u64;
                }
            });
        }
    });
    found.load(Ordering::Relaxed).to_le_bytes()
}

pub fn grind_seq(transcript_state: &[u8], bits: u32) -> [u8; 8] {
    let target = 1u64 << (64 - bits);
    let mut i = 0u64;
    loop {
        let mut cat = transcript_state.to_vec();
        cat.extend_from_slice(&i.to_le_bytes());
        let h = sha256f(&cat);
        let v = u64::from_le_bytes(h[..8].try_into().unwrap());
        if v < target {
            return i.to_le_bytes();
        }
        i += 1;
    }
}

pub fn ext_challenge(fs: &mut Fs) -> (u64, u64) {
    // GF(p^2) challenge: two base challenges (matches native_ct_air_stark _ext_challenge)
    let a0 = fs.challenge();
    let a1 = fs.challenge();
    (a0, a1)
}
