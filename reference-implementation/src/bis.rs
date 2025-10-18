use hybrid_array::{typenum::*, Array, ArraySize};
use rand::{CryptoRng, Rng};
use std::ops::{Add, Sub};

pub type Bytes<N> = Array<u8, N>;

pub trait SeedSize {
    type SeedSize: ArraySize;
}

pub type Seed<T> = Bytes<<T as SeedSize>::SeedSize>;

pub trait SharedSecretSize {
    type SharedSecretSize: ArraySize;
}

pub type SharedSecret<T> = Bytes<<T as SharedSecretSize>::SharedSecretSize>;

pub trait NominalGroup: SeedSize + SharedSecretSize {
    type ScalarSize: ArraySize;
    type ElementSize: ArraySize;

    const G: Element<Self>;

    fn random_scalar(seed: Seed<Self>) -> Scalar<Self>;
    fn exp(element: &Element<Self>, scalar: &Scalar<Self>) -> Element<Self>;
    fn element_to_shared_secret(element: Element<Self>) -> SharedSecret<Self>;
}

pub type Scalar<T> = Bytes<<T as NominalGroup>::ScalarSize>;
pub type Element<T> = Bytes<<T as NominalGroup>::ElementSize>;

pub trait Kem: SeedSize + SharedSecretSize {
    type EncapsulationKeySize: ArraySize;
    type DecapsulationKeySize: ArraySize;
    type CiphertextSize: ArraySize;

    fn derive_key_pair(seed: Seed<Self>) -> (DecapsulationKey<Self>, EncapsulationKey<Self>);

    fn encaps(
        ek: &EncapsulationKey<Self>,
        rng: &mut impl CryptoRng,
    ) -> (SharedSecret<Self>, Ciphertext<Self>);

    fn decaps(dk: &DecapsulationKey<Self>, ct: &Ciphertext<Self>) -> SharedSecret<Self>;
}

pub type EncapsulationKey<T> = Bytes<<T as Kem>::EncapsulationKeySize>;
pub type DecapsulationKey<T> = Bytes<<T as Kem>::DecapsulationKeySize>;
pub type Ciphertext<T> = Bytes<<T as Kem>::CiphertextSize>;

/// Marker trait for traditional KEMs
pub trait TKem: Kem {}

/// Marker trait for post-quantum KEMs
pub trait PqKem: Kem {}

pub trait Kdf {
    type OutputSize: ArraySize;

    fn compute(input: impl Iterator<Item = u8>) -> Output<Self>;
}

pub type Output<T> = Bytes<<T as Kdf>::OutputSize>;

pub trait Prg {
    fn generate<N: ArraySize>(seed: &[u8]) -> Bytes<N>;
}

pub type FullSeed<PQ, T> = Bytes<Sum<<PQ as SeedSize>::SeedSize, <T as SeedSize>::SeedSize>>;

// TODO: Make seed a fixed-length thing
fn expand_decaps_key_group<PQ: PqKem, T: NominalGroup, PRG: Prg, N: ArraySize>(
    seed: &Bytes<N>,
) -> (
    DecapsulationKey<PQ>,
    Scalar<T>,
    EncapsulationKey<PQ>,
    Element<T>,
)
where
    PQ::SeedSize: Add<T::SeedSize>,
    Sum<PQ::SeedSize, T::SeedSize>: ArraySize + Sub<PQ::SeedSize, Output = T::SeedSize>,
{
    let seed_full: FullSeed<PQ, T> = PRG::generate(&seed);
    let (seed_pq, seed_t) = seed_full.split();

    let (dk_pq, ek_pq) = PQ::derive_key_pair(seed_pq);
    let dk_t = T::random_scalar(seed_t);
    let ek_t = T::exp(&T::G, &dk_t);

    (dk_pq, dk_t, ek_pq, ek_t)
}

fn prepare_encaps_group<PQ: PqKem, T: NominalGroup>(
    ek_pq: &EncapsulationKey<PQ>,
    ek_t: &Element<T>,
    rng: &mut impl CryptoRng,
) -> (
    SharedSecret<PQ>,
    SharedSecret<T>,
    Ciphertext<PQ>,
    Element<T>,
) {
    let (ss_pq, ct_pq) = PQ::encaps(&ek_pq, rng);

    let mut seed_e: Seed<T> = Default::default();
    let seed_content: &mut [u8] = seed_e.as_mut();
    rng.fill(seed_content);
    let sk_e = T::random_scalar(seed_e);
    let ct_t = T::exp(&T::G, &sk_e);
    let ss_t = T::element_to_shared_secret(T::exp(&ek_t, &sk_e));

    (ss_pq, ss_t, ct_pq, ct_t)
}

fn prepare_decaps_group<PQ: PqKem, T: NominalGroup>(
    ct_pq: &Ciphertext<PQ>,
    ct_t: &Element<T>,
    dk_pq: &DecapsulationKey<PQ>,
    dk_t: &Scalar<T>,
) -> (SharedSecret<PQ>, SharedSecret<T>) {
    let ss_pq = PQ::decaps(dk_pq, ct_pq);
    let ss_t = T::element_to_shared_secret(T::exp(ct_t, dk_t));
    (ss_pq, ss_t)
}

// TODO: Make seed a fixed-length thing
fn expand_decaps_key_kem<PQ: PqKem, T: TKem, PRG: Prg, N: ArraySize>(
    seed: &Bytes<N>,
) -> (
    DecapsulationKey<PQ>,
    DecapsulationKey<T>,
    EncapsulationKey<PQ>,
    EncapsulationKey<T>,
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

fn prepare_encaps_kem<PQ: PqKem, T: TKem>(
    ek_pq: &EncapsulationKey<PQ>,
    ek_t: &EncapsulationKey<T>,
    rng: &mut impl CryptoRng,
) -> (
    SharedSecret<PQ>,
    SharedSecret<T>,
    Ciphertext<PQ>,
    Ciphertext<T>,
) {
    let (ss_pq, ct_pq) = PQ::encaps(&ek_pq, rng);
    let (ss_t, ct_t) = T::encaps(&ek_t, rng);
    (ss_pq, ss_t, ct_pq, ct_t)
}

fn prepare_decaps_kem<PQ: PqKem, T: TKem>(
    ct_pq: &Ciphertext<PQ>,
    ct_t: &Ciphertext<T>,
    dk_pq: &DecapsulationKey<PQ>,
    dk_t: &DecapsulationKey<T>,
) -> (SharedSecret<PQ>, SharedSecret<T>) {
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

pub trait HybridKemConstants: SeedSize {
    const LABEL: &[u8];
    type SharedSecretSize: ArraySize;
}

#[derive(Default)]
pub struct GU<PQ, T, P, K, C> {
    _phantom: core::marker::PhantomData<(PQ, T, P, K, C)>,
}

impl<PQ, T, P, K, C> SeedSize for GU<PQ, T, P, K, C>
where
    C: SeedSize,
{
    type SeedSize = C::SeedSize;
}

impl<PQ, T, P, K, C> SharedSecretSize for GU<PQ, T, P, K, C>
where
    C: HybridKemConstants,
{
    type SharedSecretSize = C::SharedSecretSize;
}

impl<PQ, T, P, K, C> Kem for GU<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: NominalGroup,
    P: Prg,
    K: Kdf<OutputSize = <C as HybridKemConstants>::SharedSecretSize>,
    C: HybridKemConstants,
    PQ::SeedSize: Add<T::SeedSize>,
    Sum<PQ::SeedSize, T::SeedSize>: ArraySize + Sub<PQ::SeedSize, Output = T::SeedSize>,
    PQ::EncapsulationKeySize: Add<T::ElementSize>,
    Sum<PQ::EncapsulationKeySize, T::ElementSize>:
        ArraySize + Sub<PQ::EncapsulationKeySize, Output = T::ElementSize>,
    PQ::CiphertextSize: Add<T::ElementSize>,
    Sum<PQ::CiphertextSize, T::ElementSize>:
        ArraySize + Sub<PQ::CiphertextSize, Output = T::ElementSize>,
{
    type EncapsulationKeySize = Sum<PQ::EncapsulationKeySize, T::ElementSize>;
    type DecapsulationKeySize = C::SeedSize;
    type CiphertextSize = Sum<PQ::CiphertextSize, T::ElementSize>;

    fn derive_key_pair(seed: Seed<Self>) -> (DecapsulationKey<Self>, EncapsulationKey<Self>) {
        let (_dk_pq, _dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P, C::SeedSize>(&seed);
        (seed, ek_pq.concat(ek_t))
    }

    fn encaps(
        ek: &EncapsulationKey<Self>,
        rng: &mut impl CryptoRng,
    ) -> (SharedSecret<Self>, Ciphertext<Self>) {
        let (ek_pq, ek_t) = ek.split_ref();
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_group::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);
        let ct_h = ct_pq.concat(ct_t);
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey<Self>, ct: &Ciphertext<Self>) -> SharedSecret<Self> {
        let (ct_pq, ct_t) = ct.split_ref();
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P, C::SeedSize>(dk);
        let (ss_pq, ss_t) = prepare_decaps_group::<PQ, T>(ct_pq, ct_t, &dk_pq, &dk_t);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, ct_pq, ct_t, &ek_pq, &ek_t, C::LABEL);
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
    type SeedSize = C::SeedSize;
}

impl<PQ, T, P, K, C> SharedSecretSize for GC<PQ, T, P, K, C>
where
    C: HybridKemConstants,
{
    type SharedSecretSize = C::SharedSecretSize;
}

impl<PQ, T, P, K, C> Kem for GC<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: NominalGroup,
    P: Prg,
    K: Kdf<OutputSize = <C as HybridKemConstants>::SharedSecretSize>,
    C: HybridKemConstants,
    PQ::SeedSize: Add<T::SeedSize>,
    Sum<PQ::SeedSize, T::SeedSize>: ArraySize + Sub<PQ::SeedSize, Output = T::SeedSize>,
    PQ::EncapsulationKeySize: Add<T::ElementSize>,
    Sum<PQ::EncapsulationKeySize, T::ElementSize>:
        ArraySize + Sub<PQ::EncapsulationKeySize, Output = T::ElementSize>,
    PQ::CiphertextSize: Add<T::ElementSize>,
    Sum<PQ::CiphertextSize, T::ElementSize>:
        ArraySize + Sub<PQ::CiphertextSize, Output = T::ElementSize>,
{
    type EncapsulationKeySize = Sum<PQ::EncapsulationKeySize, T::ElementSize>;
    type DecapsulationKeySize = C::SeedSize;
    type CiphertextSize = Sum<PQ::CiphertextSize, T::ElementSize>;

    fn derive_key_pair(seed: Seed<Self>) -> (DecapsulationKey<Self>, EncapsulationKey<Self>) {
        let (_dk_pq, _dk_t, ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P, C::SeedSize>(&seed);
        (seed, ek_pq.concat(ek_t))
    }

    fn encaps(
        ek: &EncapsulationKey<Self>,
        rng: &mut impl CryptoRng,
    ) -> (SharedSecret<Self>, Ciphertext<Self>) {
        let (ek_pq, ek_t) = ek.split_ref();
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_group::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);
        let ct_h = ct_pq.concat(ct_t);
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey<Self>, ct: &Ciphertext<Self>) -> SharedSecret<Self> {
        let (ct_pq, ct_t) = ct.split_ref();
        let (dk_pq, dk_t, _ek_pq, ek_t) = expand_decaps_key_group::<PQ, T, P, C::SeedSize>(dk);
        let (ss_pq, ss_t) = prepare_decaps_group::<PQ, T>(ct_pq, ct_t, &dk_pq, &dk_t);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, ct_t, &ek_t, C::LABEL);
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
    type SeedSize = C::SeedSize;
}

impl<PQ, T, P, K, C> SharedSecretSize for KU<PQ, T, P, K, C>
where
    C: HybridKemConstants,
{
    type SharedSecretSize = C::SharedSecretSize;
}

impl<PQ, T, P, K, C> Kem for KU<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: TKem,
    P: Prg,
    K: Kdf<OutputSize = <C as HybridKemConstants>::SharedSecretSize>,
    C: HybridKemConstants,
    PQ::SeedSize: Add<T::SeedSize>,
    Sum<PQ::SeedSize, T::SeedSize>: ArraySize + Sub<PQ::SeedSize, Output = T::SeedSize>,
    PQ::EncapsulationKeySize: Add<T::EncapsulationKeySize>,
    Sum<PQ::EncapsulationKeySize, T::EncapsulationKeySize>:
        ArraySize + Sub<PQ::EncapsulationKeySize, Output = T::EncapsulationKeySize>,
    PQ::CiphertextSize: Add<T::CiphertextSize>,
    Sum<PQ::CiphertextSize, T::CiphertextSize>:
        ArraySize + Sub<PQ::CiphertextSize, Output = T::CiphertextSize>,
{
    type EncapsulationKeySize = Sum<PQ::EncapsulationKeySize, T::EncapsulationKeySize>;
    type DecapsulationKeySize = C::SeedSize;
    type CiphertextSize = Sum<PQ::CiphertextSize, T::CiphertextSize>;

    fn derive_key_pair(seed: Seed<Self>) -> (DecapsulationKey<Self>, EncapsulationKey<Self>) {
        let (_dk_pq, _dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P, C::SeedSize>(&seed);
        (seed, ek_pq.concat(ek_t))
    }

    fn encaps(
        ek: &EncapsulationKey<Self>,
        rng: &mut impl CryptoRng,
    ) -> (SharedSecret<Self>, Ciphertext<Self>) {
        let (ek_pq, ek_t) = ek.split_ref();
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_kem::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, &ct_pq, &ct_t, &ek_pq, &ek_t, C::LABEL);
        let ct_h = ct_pq.concat(ct_t);
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey<Self>, ct: &Ciphertext<Self>) -> SharedSecret<Self> {
        let (ct_pq, ct_t) = ct.split_ref();
        let (dk_pq, dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P, C::SeedSize>(dk);
        let (ss_pq, ss_t) = prepare_decaps_kem::<PQ, T>(ct_pq, ct_t, &dk_pq, &dk_t);
        let ss_h = universal_combiner::<K>(&ss_pq, &ss_t, ct_pq, ct_t, &ek_pq, &ek_t, C::LABEL);
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
    type SeedSize = C::SeedSize;
}

impl<PQ, T, P, K, C> SharedSecretSize for KC<PQ, T, P, K, C>
where
    C: HybridKemConstants,
{
    type SharedSecretSize = C::SharedSecretSize;
}

impl<PQ, T, P, K, C> Kem for KC<PQ, T, P, K, C>
where
    PQ: PqKem,
    T: TKem,
    P: Prg,
    K: Kdf<OutputSize = <C as HybridKemConstants>::SharedSecretSize>,
    C: HybridKemConstants,
    PQ::SeedSize: Add<T::SeedSize>,
    Sum<PQ::SeedSize, T::SeedSize>: ArraySize + Sub<PQ::SeedSize, Output = T::SeedSize>,
    PQ::EncapsulationKeySize: Add<T::EncapsulationKeySize>,
    Sum<PQ::EncapsulationKeySize, T::EncapsulationKeySize>:
        ArraySize + Sub<PQ::EncapsulationKeySize, Output = T::EncapsulationKeySize>,
    PQ::CiphertextSize: Add<T::CiphertextSize>,
    Sum<PQ::CiphertextSize, T::CiphertextSize>:
        ArraySize + Sub<PQ::CiphertextSize, Output = T::CiphertextSize>,
{
    type EncapsulationKeySize = Sum<PQ::EncapsulationKeySize, T::EncapsulationKeySize>;
    type DecapsulationKeySize = C::SeedSize;
    type CiphertextSize = Sum<PQ::CiphertextSize, T::CiphertextSize>;

    fn derive_key_pair(seed: Seed<Self>) -> (DecapsulationKey<Self>, EncapsulationKey<Self>) {
        let (_dk_pq, _dk_t, ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P, C::SeedSize>(&seed);
        (seed, ek_pq.concat(ek_t))
    }

    fn encaps(
        ek: &EncapsulationKey<Self>,
        rng: &mut impl CryptoRng,
    ) -> (SharedSecret<Self>, Ciphertext<Self>) {
        let (ek_pq, ek_t) = ek.split_ref();
        let (ss_pq, ss_t, ct_pq, ct_t) = prepare_encaps_kem::<PQ, T>(&ek_pq, &ek_t, rng);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, &ct_t, &ek_t, C::LABEL);
        let ct_h = ct_pq.concat(ct_t);
        (ss_h, ct_h)
    }

    fn decaps(dk: &DecapsulationKey<Self>, ct: &Ciphertext<Self>) -> SharedSecret<Self> {
        let (ct_pq, ct_t) = ct.split_ref();
        let (dk_pq, dk_t, _ek_pq, ek_t) = expand_decaps_key_kem::<PQ, T, P, C::SeedSize>(dk);
        let (ss_pq, ss_t) = prepare_decaps_kem::<PQ, T>(ct_pq, ct_t, &dk_pq, &dk_t);
        let ss_h = c2pri_combiner::<K>(&ss_pq, &ss_t, ct_t, &ek_t, C::LABEL);
        ss_h
    }
}
