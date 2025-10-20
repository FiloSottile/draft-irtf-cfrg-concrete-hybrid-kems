use crate::group::*;
use crate::kdf::*;
use crate::kem::*;
use crate::prg::*;
use rand::{CryptoRng, Rng};

/// Split a vector into two parts
fn split(v: &[u8], m: usize, n: usize) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(
        v.len(),
        m + n,
        "split: expected length {}, got {}",
        m + n,
        v.len()
    );
    let first = v[..m].to_vec();
    let second = v[m..].to_vec();
    (first, second)
}

fn expand_decaps_key_group<PQ: PqKem, T: NominalGroup, PRG: Prg>(
    seed: &[u8],
) -> (DecapsulationKey, Scalar, EncapsulationKey, Element) {
    let mut prg = PRG::new(seed);

    let (dk_pq, ek_pq, _key_info) = PQ::generate_key_pair(&mut prg);
    let dk_t = T::random_scalar(&mut prg);
    let ek_t = T::exp(&T::generator(), &dk_t);

    (dk_pq, dk_t, ek_pq, ek_t)
}

fn prepare_encaps_group<PQ: PqKem, T: NominalGroup>(
    ek_pq: &EncapsulationKey,
    ek_t: &Element,
    rng: &mut impl CryptoRng,
) -> (SharedSecret, SharedSecret, Ciphertext, Element) {
    let (ss_pq, ct_pq) = PQ::encaps(&ek_pq, rng);

    let sk_e = T::random_scalar(rng);
    let ct_t = T::exp(&T::generator(), &sk_e);
    let ss_t = T::element_to_shared_secret(&T::exp(&ek_t, &sk_e));

    println!("ct_len pq={} t={}", ct_pq.len(), ct_t.len());

    (ss_pq, ss_t, ct_pq, ct_t)
}

fn prepare_decaps_group<PQ: PqKem, T: NominalGroup>(
    ct_pq: &Ciphertext,
    ct_t: &Element,
    dk_pq: &DecapsulationKey,
    dk_t: &Scalar,
) -> (SharedSecret, SharedSecret) {
    let ss_pq = PQ::decaps(dk_pq, ct_pq);
    let ss_t = T::element_to_shared_secret(&T::exp(ct_t, dk_t));
    (ss_pq, ss_t)
}

fn expand_decaps_key_kem<PQ: PqKem, T: TKem, PRG: Prg>(
    seed: &[u8],
) -> (
    DecapsulationKey,
    DecapsulationKey,
    EncapsulationKey,
    EncapsulationKey,
) {
    let mut prg = PRG::new(seed);

    let (dk_pq, ek_pq, _key_info) = PQ::generate_key_pair(&mut prg);
    let (dk_t, ek_t, _key_info) = T::generate_key_pair(&mut prg);

    (dk_pq, dk_t, ek_pq, ek_t)
}

fn prepare_encaps_kem<PQ: PqKem, T: TKem>(
    ek_pq: &EncapsulationKey,
    ek_t: &EncapsulationKey,
    rng: &mut impl CryptoRng,
) -> (SharedSecret, SharedSecret, Ciphertext, Ciphertext) {
    let (ss_pq, ct_pq) = PQ::encaps(&ek_pq, rng);
    let (ss_t, ct_t) = T::encaps(&ek_t, rng);
    (ss_pq, ss_t, ct_pq, ct_t)
}

fn prepare_decaps_kem<PQ: PqKem, T: TKem>(
    ct_pq: &Ciphertext,
    ct_t: &Ciphertext,
    dk_pq: &DecapsulationKey,
    dk_t: &DecapsulationKey,
) -> (SharedSecret, SharedSecret) {
    let ss_pq = PQ::decaps(dk_pq, ct_pq);
    let ss_t = T::decaps(dk_t, ct_t);
    (ss_pq, ss_t)
}

fn universal_combiner<K: Kdf>(
    ss_pq: &[u8],
    ss_t: &[u8],
    ct_pq: &[u8],
    ct_t: &[u8],
    ek_pq: &[u8],
    ek_t: &[u8],
    label: &[u8],
) -> Output {
    K::compute(
        ss_pq
            .iter()
            .chain(ss_t.iter())
            .chain(ct_pq.iter())
            .chain(ct_t.iter())
            .chain(ek_pq.iter())
            .chain(ek_t.iter())
            .chain(label.iter())
            .cloned(),
    )
}

fn c2pri_combiner<K: Kdf>(
    ss_pq: &[u8],
    ss_t: &[u8],
    ct_t: &[u8],
    ek_t: &[u8],
    label: &[u8],
) -> Output {
    K::compute(
        ss_pq
            .iter()
            .chain(ss_t.iter())
            .chain(ct_t.iter())
            .chain(ek_t.iter())
            .chain(label.iter())
            .cloned(),
    )
}

pub trait HybridKemConstants: SeedSize + SharedSecretSize {
    const LABEL: &'static [u8];
}

// We use this struct to smuggle out intermediate values to the test vectors
pub struct HybridSubKeys {
    pub dk_pq: Vec<u8>,
    pub dk_t: Vec<u8>,
}

pub trait HybridKem: Kem<KeyInfo = HybridSubKeys> {}

impl<K> HybridKem for K where K: Kem<KeyInfo = HybridSubKeys> {}

#[derive(Default)]
pub struct GU<PQ, T, P, K, C> {
    _phantom: core::marker::PhantomData<(PQ, T, P, K, C)>,
}

impl<PQ, T, P, K, C> SeedSize for GU<PQ, T, P, K, C>
where
    C: SeedSize,
{
    const SEED_SIZE: usize = C::SEED_SIZE;
}

impl<PQ, T, P, K, C> SharedSecretSize for GU<PQ, T, P, K, C>
where
    C: SharedSecretSize,
{
    const SHARED_SECRET_SIZE: usize = C::SHARED_SECRET_SIZE;
}

impl<PQ, T, P, K, C> Kem for GU<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: NominalGroup,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const ENCAPS_RANDOMNESS_SIZE: usize = PQ::ENCAPS_RANDOMNESS_SIZE + T::SEED_SIZE;
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ELEMENT_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::ELEMENT_SIZE;

    type KeyInfo = HybridSubKeys;

    fn generate_key_pair(
        prg: &mut impl CryptoRng,
    ) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo) {
        let mut seed = vec![0u8; Self::SEED_SIZE];
        prg.fill(seed.as_mut_slice());

        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek, HybridSubKeys { dk_pq, dk_t })
    }

    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ELEMENT_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_group::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);
        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret {
        assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
        assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
        let (ct_pq, ct_t) = split(ct, PQ::CIPHERTEXT_SIZE, T::ELEMENT_SIZE);
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P>(dk);
        let (ss_pq, ss_t) = prepare_decaps_group::<PQ, T>(&ct_pq, &ct_t, &dk_pq, &dk_t);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);
        ss_h
    }
}

#[derive(Default)]
pub struct GC<PQ, T, P, K, C> {
    _phantom: core::marker::PhantomData<(PQ, T, P, K, C)>,
}

impl<PQ, T, P, K, C> SeedSize for GC<PQ, T, P, K, C>
where
    C: SeedSize,
{
    const SEED_SIZE: usize = C::SEED_SIZE;
}

impl<PQ, T, P, K, C> SharedSecretSize for GC<PQ, T, P, K, C>
where
    C: SharedSecretSize,
{
    const SHARED_SECRET_SIZE: usize = C::SHARED_SECRET_SIZE;
}

impl<PQ, T, P, K, C> Kem for GC<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: NominalGroup,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const ENCAPS_RANDOMNESS_SIZE: usize = PQ::ENCAPS_RANDOMNESS_SIZE + T::SEED_SIZE;
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ELEMENT_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::ELEMENT_SIZE;

    type KeyInfo = HybridSubKeys;

    fn generate_key_pair(
        prg: &mut impl CryptoRng,
    ) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo) {
        let mut seed = vec![0u8; Self::SEED_SIZE];
        prg.fill(seed.as_mut_slice());

        assert_eq!(seed.len(), Self::SEED_SIZE);
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek, HybridSubKeys { dk_pq, dk_t })
    }

    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ELEMENT_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_group::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);

        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());

        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret {
        assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
        assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
        let (ct_pq, ct_t) = split(ct, PQ::CIPHERTEXT_SIZE, T::ELEMENT_SIZE);
        let (dk_pq, dk_t, _ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P>(dk);
        let (ss_pq, ss_t) = prepare_decaps_group::<PQ, T>(&ct_pq, &ct_t, &dk_pq, &dk_t);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);
        ss_h
    }
}

#[derive(Default)]
pub struct KU<PQ, T, P, K, C> {
    _phantom: core::marker::PhantomData<(PQ, T, P, K, C)>,
}

impl<PQ, T, P, K, C> SeedSize for KU<PQ, T, P, K, C>
where
    C: SeedSize,
{
    const SEED_SIZE: usize = C::SEED_SIZE;
}

impl<PQ, T, P, K, C> SharedSecretSize for KU<PQ, T, P, K, C>
where
    C: SharedSecretSize,
{
    const SHARED_SECRET_SIZE: usize = C::SHARED_SECRET_SIZE;
}

impl<PQ, T, P, K, C> Kem for KU<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: TKem,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const ENCAPS_RANDOMNESS_SIZE: usize = PQ::ENCAPS_RANDOMNESS_SIZE + T::ENCAPS_RANDOMNESS_SIZE;
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ENCAPSULATION_KEY_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::CIPHERTEXT_SIZE;

    type KeyInfo = HybridSubKeys;

    fn generate_key_pair(
        prg: &mut impl CryptoRng,
    ) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo) {
        let mut seed = vec![0u8; Self::SEED_SIZE];
        prg.fill(seed.as_mut_slice());

        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek, HybridSubKeys { dk_pq, dk_t })
    }

    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ENCAPSULATION_KEY_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_kem::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);
        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret {
        assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
        assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
        let (ct_pq, ct_t) = split(ct, PQ::CIPHERTEXT_SIZE, T::CIPHERTEXT_SIZE);
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P>(dk);
        let (ss_pq, ss_t) = prepare_decaps_kem::<PQ, T>(&ct_pq, &ct_t, &dk_pq, &dk_t);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);
        ss_h
    }
}

#[derive(Default)]
pub struct KC<PQ, T, P, K, C> {
    _phantom: core::marker::PhantomData<(PQ, T, P, K, C)>,
}

impl<PQ, T, P, K, C> SeedSize for KC<PQ, T, P, K, C>
where
    C: SeedSize,
{
    const SEED_SIZE: usize = C::SEED_SIZE;
}

impl<PQ, T, P, K, C> SharedSecretSize for KC<PQ, T, P, K, C>
where
    C: SharedSecretSize,
{
    const SHARED_SECRET_SIZE: usize = C::SHARED_SECRET_SIZE;
}

impl<PQ, T, P, K, C> Kem for KC<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: TKem,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const ENCAPS_RANDOMNESS_SIZE: usize = PQ::ENCAPS_RANDOMNESS_SIZE + T::ENCAPS_RANDOMNESS_SIZE;
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ENCAPSULATION_KEY_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::CIPHERTEXT_SIZE;

    type KeyInfo = HybridSubKeys;

    fn generate_key_pair(
        prg: &mut impl CryptoRng,
    ) -> (DecapsulationKey, EncapsulationKey, Self::KeyInfo) {
        let mut seed = vec![0u8; Self::SEED_SIZE];
        prg.fill(seed.as_mut_slice());

        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek, HybridSubKeys { dk_pq, dk_t })
    }

    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ENCAPSULATION_KEY_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_kem::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);
        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret {
        assert_eq!(dk.len(), Self::DECAPSULATION_KEY_SIZE);
        assert_eq!(ct.len(), Self::CIPHERTEXT_SIZE);
        let (ct_pq, ct_t) = split(ct, PQ::CIPHERTEXT_SIZE, T::CIPHERTEXT_SIZE);
        let (dk_pq, dk_t, _ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P>(dk);
        let (ss_pq, ss_t) = prepare_decaps_kem::<PQ, T>(&ct_pq, &ct_t, &dk_pq, &dk_t);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);
        ss_h
    }
}
