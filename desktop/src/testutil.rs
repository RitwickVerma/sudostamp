//! Seeded randomness for the property tests, like the repo's other fuzz tests: a failure prints its
//! seed, `SUDOSTAMP_FUZZ_SEED=N` replays it, `SUDOSTAMP_FUZZ_ITERATIONS=N` scales the run.

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    /// xorshift64*: tiny, fast, good enough to aim hostile input at a parser.
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n.max(1) as u64)).unwrap_or(0)
    }

    /// Up to `max` random bytes.
    pub fn junk(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        self.bytes(n)
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next().to_le_bytes()[3]).collect()
    }
}

pub fn iterations() -> usize {
    std::env::var("SUDOSTAMP_FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

pub fn seed() -> u64 {
    std::env::var("SUDOSTAMP_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x5AD0_5741)
}
