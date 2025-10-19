use rand::{CryptoRng, RngCore};
use sha3::{digest::XofReader, Shake256Reader};

pub trait Prg: CryptoRng {
    fn new(seed: &[u8]) -> Self;
}

/// SHAKE256 based PRG with generic output length
pub struct Shake256(Shake256Reader);

impl Prg for Shake256 {
    fn new(seed: &[u8]) -> Self {
        use sha3::digest::{ExtendableOutput, Update};
        let mut shake = sha3::Shake256::default();
        shake.update(seed);
        let reader = shake.finalize_xof();
        Self(reader)
    }
}

impl CryptoRng for Shake256 {}

impl RngCore for Shake256 {
    fn next_u32(&mut self) -> u32 {
        let mut data = [0; 4];
        self.0.read(&mut data);
        u32::from_be_bytes(data)
    }

    fn next_u64(&mut self) -> u64 {
        let mut data = [0; 8];
        self.0.read(&mut data);
        u64::from_be_bytes(data)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }
}

impl old_rand_core::CryptoRng for Shake256 {}

impl old_rand_core::RngCore for Shake256 {
    fn next_u32(&mut self) -> u32 {
        let mut data = [0; 4];
        self.0.read(&mut data);
        u32::from_be_bytes(data)
    }

    fn next_u64(&mut self) -> u64 {
        let mut data = [0; 8];
        self.0.read(&mut data);
        u64::from_be_bytes(data)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.read(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), old_rand_core::Error> {
        Ok(self.0.read(dest))
    }
}

pub struct TrivialPrg(Vec<u8>);

impl Prg for TrivialPrg {
    fn new(seed: &[u8]) -> Self {
        Self(seed.to_vec())
    }
}

impl TrivialPrg {
    fn read(&mut self, out: &mut [u8]) {
        let last = self.0.split_off(out.len());
        out.copy_from_slice(&self.0);
        self.0 = last;
    }
}

impl CryptoRng for TrivialPrg {}

impl RngCore for TrivialPrg {
    fn next_u32(&mut self) -> u32 {
        let mut data = [0; 4];
        self.read(&mut data);
        u32::from_be_bytes(data)
    }

    fn next_u64(&mut self) -> u64 {
        let mut data = [0; 8];
        self.read(&mut data);
        u64::from_be_bytes(data)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.read(dest);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    pub fn test_all<P: Prg>() {
        // Create test seed
        let seed: Vec<u8> = (0..32)
            .map(|i| (i as u8).wrapping_mul(23).wrapping_add(77))
            .collect();

        // Test that the whole output is filled
        let canary = 0xA0;
        let mut output = [canary; 128];
        let mut prg = P::new(&seed);
        prg.fill(&mut output);
        let count = output.iter().filter(|x| **x == canary).count();
        assert!(count < 2, "PRG incomplete fill");

        // Test determinism
        let mut output2 = [0; 128];
        let mut prg = P::new(&seed);
        prg.fill(&mut output2);
        assert_eq!(output, output2, "PRG should be deterministic");

        // Test different seeds produce different outputs
        let mut seed2 = seed.clone();
        seed2[0] = seed2[0].wrapping_add(1);
        let mut prg = P::new(&seed2);
        prg.fill(&mut output2);
        assert_ne!(
            output, output2,
            "Different seeds should produce different outputs"
        );
    }

    #[test]
    fn shake256() {
        test_all::<Shake256>();
    }
}
