use anyhow::Result;
use ff::FromUniformBytes;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::pallas::Scalar;
use primitive_types::H256;
use sha3::{self, Digest};

pub(crate) fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(bytes);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hasher.finalize().as_slice());
    Scalar::from_uniform_bytes(&bytes)
}

pub(crate) fn get_random_scalar() -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)?;
    Ok(hash_to_scalar(&bytes))
}

pub(crate) fn get_random_bytes() -> Result<H256> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)?;
    Ok(H256::from_slice(&bytes))
}

/// Hashes a sequence of scalars with Poseidon (using `P128Pow5T3`).
pub(crate) fn poseidon_hash<const L: usize>(inputs: [Scalar; L]) -> Scalar {
    let hasher = Hash::<Scalar, P128Pow5T3, ConstantLength<L>, 3, 2>::init();
    hasher.hash(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use primitive_types::U256;

    #[test]
    fn test_hash_to_scalar() {
        let hash = hash_to_scalar(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        assert_eq!(
            U256::from_little_endian(&hash.to_repr()),
            "0x2e467e7f2365fc459cdac50ac49e178ac634b2ba9b9b2e5886757ae23db2bfa4"
                .parse()
                .unwrap()
        );
    }
}
