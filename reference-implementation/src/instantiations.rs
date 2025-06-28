//! Concrete hybrid KEM instantiations

use crate::{
    groups::{P256Group, P384Group, X25519Group},
    kems::{MlKem768Kem, MlKem1024},
    primitives::{Sha3_256Kdf, Shake256Prg},
};
use hybrid_kem_ref::{qsf::QsfHybridKem, traits::HybridKemLabel};

// Calculate output lengths for SHAKE256 PRG
const P256_MLKEM768_PRG_OUTPUT: usize = 48 + 64; // P256::SEED_LENGTH + MlKem768::SEED_LENGTH
const X25519_MLKEM768_PRG_OUTPUT: usize = 32 + 64; // X25519::SEED_LENGTH + MlKem768::SEED_LENGTH  
const P384_MLKEM1024_PRG_OUTPUT: usize = 72 + 64; // P384::SEED_LENGTH + MlKem1024::SEED_LENGTH

/// Label for QSF-P256-MLKEM768-SHAKE256-SHA3256 hybrid KEM
pub struct QsfP256MlKem768Shake256Sha3256Label;

impl HybridKemLabel for QsfP256MlKem768Shake256Sha3256Label {
    const LABEL: &'static [u8] = b"QSF-P256-MLKEM768-SHAKE256-SHA3256";
}

/// QSF-P256-MLKEM768-SHAKE256-SHA3256 hybrid KEM
pub type QsfP256MlKem768Shake256Sha3256 = QsfHybridKem<
    P256Group,
    MlKem768Kem,
    Sha3_256Kdf,
    Shake256Prg<P256_MLKEM768_PRG_OUTPUT>,
    QsfP256MlKem768Shake256Sha3256Label,
>;

/// Label for QSF-X25519-MLKEM768-SHAKE256-SHA3256 hybrid KEM (X-Wing compatible)
pub struct QsfX25519MlKem768Shake256Sha3256Label;

impl HybridKemLabel for QsfX25519MlKem768Shake256Sha3256Label {
    // X-Wing compatible label
    const LABEL: &'static [u8] = b"\\.//^\\";
}

/// QSF-X25519-MLKEM768-SHAKE256-SHA3256 hybrid KEM (X-Wing)
pub type QsfX25519MlKem768Shake256Sha3256 = QsfHybridKem<
    X25519Group,
    MlKem768Kem,
    Sha3_256Kdf,
    Shake256Prg<X25519_MLKEM768_PRG_OUTPUT>,
    QsfX25519MlKem768Shake256Sha3256Label,
>;

/// Label for QSF-P384-MLKEM1024-SHAKE256-SHA3256 hybrid KEM
pub struct QsfP384MlKem1024Shake256Sha3256Label;

impl HybridKemLabel for QsfP384MlKem1024Shake256Sha3256Label {
    const LABEL: &'static [u8] = b"QSF-P384-MLKEM1024-SHAKE256-SHA3256";
}

/// QSF-P384-MLKEM1024-SHAKE256-SHA3256 hybrid KEM
pub type QsfP384MlKem1024Shake256Sha3256 = QsfHybridKem<
    P384Group,
    MlKem1024,
    Sha3_256Kdf,
    Shake256Prg<P384_MLKEM1024_PRG_OUTPUT>,
    QsfP384MlKem1024Shake256Sha3256Label,
>;
