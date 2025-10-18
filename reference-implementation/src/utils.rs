//! Utility functions and wrappers

/// RNG wrapper to bridge between rand_core versions
pub struct RngWrapper<'a, R: rand::CryptoRng>(pub &'a mut R);

impl<'a, R> old_rand_core::RngCore for RngWrapper<'a, R>
where
    R: rand::CryptoRng,
{
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), old_rand_core::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<'a, R> old_rand_core::CryptoRng for RngWrapper<'a, R> where R: rand::CryptoRng {}

/// Fixed RNG for deterministic testing
pub struct FixedRng {
    data: Vec<u8>,
    position: usize,
}

impl FixedRng {
    /// Create a new FixedRng from seed data
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            position: 0,
        }
    }
}

impl rand::RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            *byte = self.data[self.position % self.data.len()];
            self.position += 1;
        }
    }
}

impl rand::CryptoRng for FixedRng {}