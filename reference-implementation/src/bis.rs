use hybrid_array::{typenum::*, Array, ArraySize};
use rand::{CryptoRng, Rng};
use std::ops::{Add, Sub};

type Bytes<N> = Array<u8, N>;

trait SeedSize {
    type SeedSize: ArraySize;
}

trait NominalGroup: SeedSize {
    type Scalar;
    type Element;
    type SharedSecret;

    const G: Self::Element;

    fn random_scalar(seed: Bytes<Self::SeedSize>) -> Self::Scalar;
    fn exp(element: &Self::Element, scalar: &Self::Scalar) -> Self::Element;
    fn element_to_shared_secret(element: Self::Element) -> Self::SharedSecret;
}

trait Kem: SeedSize {
    type EncapsulationKey;
    type DecapsulationKey;
    type Ciphertext;
    type SharedSecret;

    fn derive_key_pair(
        seed: Bytes<Self::SeedSize>,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey);

    fn encaps(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRng,
    ) -> (Self::SharedSecret, Self::Ciphertext);

    fn decaps(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Self::SharedSecret;
}

/// Marker trait for traditional KEMs
trait TKem: Kem {}

/// Marker trait for post-quantum KEMs
trait PqKem: Kem {}

trait Combiner {}

trait Kdf {
    type OutputSize: ArraySize;

    fn compute(input: impl Iterator<Item = u8>) -> Bytes<Self::OutputSize>;
}

trait Prg {
    fn generate<N: ArraySize>(seed: &[u8]) -> Bytes<N>;
}

type FullSeed<PQ, T> = Bytes<Sum<<PQ as SeedSize>::SeedSize, <T as SeedSize>::SeedSize>>;

// TODO: Make seed a fixed-length thing
fn expand_decaps_key_group<PQ: PqKem, T: NominalGroup, PRG: Prg>(
    seed: &[u8],
) -> (
    PQ::DecapsulationKey,
    T::Scalar,
    PQ::EncapsulationKey,
    T::Element,
)
where
    PQ::SeedSize: Add<T::SeedSize>,
    Sum<PQ::SeedSize, T::SeedSize>: ArraySize + Sub<PQ::SeedSize, Output = T::SeedSize>,
{
    let seed_full: FullSeed<PQ, T> = PRG::generate(seed);
    let (seed_pq, seed_t) = seed_full.split();

    let (dk_pq, ek_pq) = PQ::derive_key_pair(seed_pq);
    let dk_t = T::random_scalar(seed_t);
    let ek_t = T::exp(&T::G, &dk_t);

    (dk_pq, dk_t, ek_pq, ek_t)
}

fn prepare_encap_group<PQ: PqKem, T: NominalGroup>(
    ek_pq: &PQ::EncapsulationKey,
    ek_t: &T::Element,
    rng: &mut impl CryptoRng,
) -> (
    PQ::SharedSecret,
    T::SharedSecret,
    PQ::Ciphertext,
    T::Element,
) {
    let (ss_pq, ct_pq) = PQ::encaps(&ek_pq, rng);

    let mut seed_e: Bytes<T::SeedSize> = Default::default();
    let seed_content: &mut [u8] = seed_e.as_mut();
    rng.fill(seed_content);
    let sk_e = T::random_scalar(seed_e);
    let ct_t = T::exp(&T::G, &sk_e);
    let ss_t = T::element_to_shared_secret(T::exp(&ek_t, &sk_e));

    (ss_pq, ss_t, ct_pq, ct_t)
}

fn prepare_decap_group<PQ: PqKem, T: NominalGroup>(
    ct_pq: &PQ::Ciphertext,
    ct_t: &T::Element,
    dk_pq: &PQ::DecapsulationKey,
    dk_t: &T::Scalar,
) -> (PQ::SharedSecret, T::SharedSecret) {
    let ss_pq = PQ::decaps(dk_pq, ct_pq);
    let ss_t = T::element_to_shared_secret(T::exp(ct_t, dk_t));
    (ss_pq, ss_t)
}

// TODO: Make seed a fixed-length thing
fn expand_decaps_key_kem<PQ: PqKem, T: TKem, PRG: Prg>(
    seed: &[u8],
) -> (
    PQ::DecapsulationKey,
    T::DecapsulationKey,
    PQ::EncapsulationKey,
    T::EncapsulationKey,
)
where
    PQ::SeedSize: Add<T::SeedSize>,
    Sum<PQ::SeedSize, T::SeedSize>: ArraySize + Sub<PQ::SeedSize, Output = T::SeedSize>,
{
    let seed_full: FullSeed<PQ, T> = PRG::generate(seed);
    let (seed_pq, seed_t) = seed_full.split();

    let (dk_pq, ek_pq) = PQ::derive_key_pair(seed_pq);
    let (dk_t, ek_t) = T::derive_key_pair(seed_t);

    (dk_pq, dk_t, ek_pq, ek_t)
}

fn prepare_encap_kem<PQ: PqKem, T: TKem>(
    ek_pq: &PQ::EncapsulationKey,
    ek_t: &T::EncapsulationKey,
    rng: &mut impl CryptoRng,
) -> (
    PQ::SharedSecret,
    T::SharedSecret,
    PQ::Ciphertext,
    T::Ciphertext,
) {
    let (ss_pq, ct_pq) = PQ::encaps(&ek_pq, rng);
    let (ss_t, ct_t) = T::encaps(&ek_t, rng);
    (ss_pq, ss_t, ct_pq, ct_t)
}

fn prepare_decap_kem<PQ: PqKem, T: TKem>(
    ct_pq: &PQ::Ciphertext,
    ct_t: &T::Ciphertext,
    dk_pq: &PQ::DecapsulationKey,
    dk_t: &T::DecapsulationKey,
) -> (PQ::SharedSecret, T::SharedSecret) {
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
) -> Bytes<K::OutputSize> {
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
) -> Bytes<K::OutputSize> {
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

trait HybridKemConstants: SeedSize {
    const LABEL: &[u8];
    type SharedSecretSize: ArraySize;
}

#[derive(Default)]
pub struct GU<PQ, T, P, K, C> {
    _phantom: core::marker::PhantomData<(PQ, T, P, K, C)>,
}

/*
impl<PQ, T, P, K, C> Kem for GU<PQ, T, P, K, L>
where
    PQ: PqKem,
    T: NominalGroup,
    P: Prg,
    K: Kdf,
    C: HybridKemConstants,
{
    type EncapsulationKey;
    type DecapsulationKey;
    type Ciphertext;
    type SharedSecret;

    fn derive_key_pair(
        seed: Bytes<Self::SeedSize>,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        todo!()
    }

    fn encaps(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRng,
    ) -> (Self::SharedSecret, Self::Ciphertext) {
        todo!()
    }

    fn decaps(dk: &Self::DecapsulationKey, ct: &Self::Ciphertext) -> Self::SharedSecret {
        todo!()
    }
}
*/
