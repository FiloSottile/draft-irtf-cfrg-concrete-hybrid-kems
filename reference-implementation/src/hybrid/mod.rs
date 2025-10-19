use rand::{CryptoRng, Rng};

#[cfg(test)]
pub mod test_utils;

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

// All of these are Vec<u8> for convenience, but we define aliases so that the method signatures
// tell you which thing is expected to be which.
pub type Seed = Vec<u8>;
pub type SharedSecret = Vec<u8>;
pub type Scalar = Vec<u8>;
pub type Element = Vec<u8>;
pub type EncapsulationKey = Vec<u8>;
pub type DecapsulationKey = Vec<u8>;
pub type Ciphertext = Vec<u8>;

pub trait SeedSize {
    const SEED_SIZE: usize;
}

pub trait SharedSecretSize {
    const SHARED_SECRET_SIZE: usize;
}

pub trait NominalGroup: SeedSize + SharedSecretSize {
    const SCALAR_SIZE: usize;
    const ELEMENT_SIZE: usize;

    fn generator() -> Element;
    fn random_scalar(seed: &[u8]) -> Scalar;
    fn exp(element: &Element, scalar: &Scalar) -> Element;
    fn element_to_shared_secret(element: &Element) -> SharedSecret;
}

pub trait Kem: SeedSize + SharedSecretSize {
    const ENCAPSULATION_KEY_SIZE: usize;
    const DECAPSULATION_KEY_SIZE: usize;
    const CIPHERTEXT_SIZE: usize;

    fn derive_key_pair(seed: &[u8]) -> (DecapsulationKey, EncapsulationKey);
    fn encaps(ek: &EncapsulationKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext);
    fn decaps(dk: &DecapsulationKey, ct: &Ciphertext) -> SharedSecret;
}

pub trait EncapsDerand: Kem {
    const RANDOMNESS_SIZE: usize;

    fn encaps_derand(ek: &EncapsulationKey, randomness: &[u8]) -> (Ciphertext, SharedSecret);
}

/// Marker trait for traditional KEMs
pub trait TKem: Kem {}

/// Marker trait for post-quantum KEMs
pub trait PqKem: Kem {}

pub trait Kdf {
    const OUTPUT_SIZE: usize;

    fn compute(input: impl Iterator<Item = u8>) -> Output;
}

pub type Output = Vec<u8>;

pub trait Prg {
    fn generate(seed: &[u8], output_len: usize) -> Vec<u8>;
}

fn expand_decaps_key_group<PQ: PqKem, T: NominalGroup, PRG: Prg>(
    seed: &[u8],
) -> (DecapsulationKey, Scalar, EncapsulationKey, Element) {
    let seed_full = PRG::generate(seed, PQ::SEED_SIZE + T::SEED_SIZE);
    let (seed_pq, seed_t) = split(&seed_full, PQ::SEED_SIZE, T::SEED_SIZE);

    let (dk_pq, ek_pq) = PQ::derive_key_pair(&seed_pq);
    let dk_t = T::random_scalar(&seed_t);
    let ek_t = T::exp(&T::generator(), &dk_t);

    (dk_pq, dk_t, ek_pq, ek_t)
}

fn prepare_encaps_group<PQ: PqKem, T: NominalGroup>(
    ek_pq: &EncapsulationKey,
    ek_t: &Element,
    rng: &mut impl CryptoRng,
) -> (SharedSecret, SharedSecret, Ciphertext, Element) {
    let (ss_pq, ct_pq) = PQ::encaps(&ek_pq, rng);

    let mut seed_e = vec![0u8; T::SEED_SIZE];
    rng.fill(seed_e.as_mut_slice());
    let sk_e = T::random_scalar(&seed_e);
    let ct_t = T::exp(&T::generator(), &sk_e);
    let ss_t = T::element_to_shared_secret(&T::exp(&ek_t, &sk_e));

    (ss_pq, ss_t, ct_pq, ct_t)
}

fn prepare_encaps_group_derand<PQ: PqKem + EncapsDerand, T: NominalGroup>(
    ek_pq: &EncapsulationKey,
    ek_t: &Element,
    randomness: &[u8],
) -> (SharedSecret, SharedSecret, Ciphertext, Element) {
    assert_eq!(
        randomness.len(),
        PQ::RANDOMNESS_SIZE + T::SEED_SIZE,
        "prepare_encaps_group_derand: expected {} bytes of randomness, got {}",
        PQ::RANDOMNESS_SIZE + T::SEED_SIZE,
        randomness.len()
    );

    let (randomness_pq, seed_e) = split(randomness, PQ::RANDOMNESS_SIZE, T::SEED_SIZE);

    let (ct_pq, ss_pq) = PQ::encaps_derand(&ek_pq, &randomness_pq);

    let sk_e = T::random_scalar(&seed_e);
    let ct_t = T::exp(&T::generator(), &sk_e);
    let ss_t = T::element_to_shared_secret(&T::exp(&ek_t, &sk_e));

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
    let seed_full = PRG::generate(seed, PQ::SEED_SIZE + T::SEED_SIZE);
    let (seed_pq, seed_t) = split(&seed_full, PQ::SEED_SIZE, T::SEED_SIZE);

    let (dk_pq, ek_pq) = PQ::derive_key_pair(&seed_pq);
    let (dk_t, ek_t) = T::derive_key_pair(&seed_t);

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
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ELEMENT_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::ELEMENT_SIZE;

    fn derive_key_pair(seed: &[u8]) -> (DecapsulationKey, EncapsulationKey) {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        let (_dk_pq, _dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek)
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

impl<PQ, T, P, K, C> EncapsDerand for GU<PQ, T, P, K, C>
where
    PQ: PqKem + EncapsDerand,
    T: NominalGroup,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const RANDOMNESS_SIZE: usize = PQ::RANDOMNESS_SIZE + T::SEED_SIZE;

    fn encaps_derand(ek: &EncapsulationKey, randomness: &[u8]) -> (Ciphertext, SharedSecret) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        assert_eq!(randomness.len(), Self::RANDOMNESS_SIZE);

        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ELEMENT_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) =
            prepare_encaps_group_derand::<PQ, T>(&ek_pq, &ek_t, randomness);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);

        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());

        (ct_h, ss_h)
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
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ELEMENT_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::ELEMENT_SIZE;

    fn derive_key_pair(seed: &[u8]) -> (DecapsulationKey, EncapsulationKey) {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        let (_dk_pq, _dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek)
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

impl<PQ, T, P, K, C> EncapsDerand for GC<PQ, T, P, K, C>
where
    PQ: PqKem + EncapsDerand,
    T: NominalGroup,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    const RANDOMNESS_SIZE: usize = PQ::RANDOMNESS_SIZE + T::SEED_SIZE;

    fn encaps_derand(ek: &EncapsulationKey, randomness: &[u8]) -> (Ciphertext, SharedSecret) {
        assert_eq!(ek.len(), Self::ENCAPSULATION_KEY_SIZE);
        assert_eq!(randomness.len(), Self::RANDOMNESS_SIZE);

        let (ek_pq, ek_t) = split(ek, PQ::ENCAPSULATION_KEY_SIZE, T::ELEMENT_SIZE);
        let (ss_pq, ss_t, ct_pq, ct_t) =
            prepare_encaps_group_derand::<PQ, T>(&ek_pq, &ek_t, randomness);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);

        let mut ct_h = ct_pq;
        ct_h.append(&mut ct_t.clone());

        (ct_h, ss_h)
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
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ENCAPSULATION_KEY_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::CIPHERTEXT_SIZE;

    fn derive_key_pair(seed: &[u8]) -> (DecapsulationKey, EncapsulationKey) {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        let (_dk_pq, _dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek)
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
    const ENCAPSULATION_KEY_SIZE: usize = PQ::ENCAPSULATION_KEY_SIZE + T::ENCAPSULATION_KEY_SIZE;
    const DECAPSULATION_KEY_SIZE: usize = C::SEED_SIZE;
    const CIPHERTEXT_SIZE: usize = PQ::CIPHERTEXT_SIZE + T::CIPHERTEXT_SIZE;

    fn derive_key_pair(seed: &[u8]) -> (DecapsulationKey, EncapsulationKey) {
        assert_eq!(seed.len(), Self::SEED_SIZE);
        let (_dk_pq, _dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P>(&seed);
        let mut ek = ek_pq;
        ek.append(&mut ek_t.clone());
        (seed.to_vec(), ek)
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

/// Constants for QSF-P256-MLKEM768-SHAKE256-SHA3256 hybrid KEM
pub struct MlKem768P256Constants;

impl SeedSize for MlKem768P256Constants {
    const SEED_SIZE: usize = 32;
}

impl SharedSecretSize for MlKem768P256Constants {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl HybridKemConstants for MlKem768P256Constants {
    const LABEL: &'static [u8] = b"|-()-|";
}

/// QSF-P256-MLKEM768-SHAKE256-SHA3256 hybrid KEM
pub type MlKem768P256 = GC<
    crate::kems::MlKem768,
    crate::groups::P256Group,
    crate::prg::Shake256Prg<112>, // 48 (P256 seed) + 64 (ML-KEM-768 seed)
    crate::kdf::Sha3_256Kdf,
    MlKem768P256Constants,
>;

/// Constants for QSF-X25519-MLKEM768-SHAKE256-SHA3256 hybrid KEM (X-Wing compatible)
pub struct MlKem768X25519Constants;

impl SeedSize for MlKem768X25519Constants {
    const SEED_SIZE: usize = 32;
}

impl SharedSecretSize for MlKem768X25519Constants {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl HybridKemConstants for MlKem768X25519Constants {
    const LABEL: &'static [u8] = b"\\.//^\\";
}

/// QSF-X25519-MLKEM768-SHAKE256-SHA3256 hybrid KEM (X-Wing)
pub type MlKem768X25519 = GC<
    crate::kems::MlKem768,
    crate::groups::X25519Group,
    crate::prg::Shake256Prg<96>, // 32 (X25519 seed) + 64 (ML-KEM-768 seed)
    crate::kdf::Sha3_256Kdf,
    MlKem768X25519Constants,
>;

/// Constants for QSF-P384-MLKEM1024-SHAKE256-SHA3256 hybrid KEM
pub struct MlKem1024P384Constants;

impl SeedSize for MlKem1024P384Constants {
    const SEED_SIZE: usize = 32;
}

impl SharedSecretSize for MlKem1024P384Constants {
    const SHARED_SECRET_SIZE: usize = 32;
}

impl HybridKemConstants for MlKem1024P384Constants {
    const LABEL: &'static [u8] = b" | /-\\";
}

/// QSF-P384-MLKEM1024-SHAKE256-SHA3256 hybrid KEM
pub type MlKem1024P384 = GC<
    crate::kems::MlKem1024,
    crate::groups::P384Group,
    crate::prg::Shake256Prg<136>, // 72 (P384 seed) + 64 (ML-KEM-1024 seed)
    crate::kdf::Sha3_256Kdf,
    MlKem1024P384Constants,
>;
