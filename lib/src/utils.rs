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

    #[test]
    fn test_random_scalars() {
        assert_ne!(get_random_scalar().unwrap(), get_random_scalar().unwrap());
    }

    #[test]
    fn test_random_bytes() {
        assert_ne!(get_random_bytes().unwrap(), get_random_bytes().unwrap());
    }

    #[test]
    fn test_poseidon_hash1() {
        assert_eq!(
            poseidon_hash([12.into(), 34.into()]),
            Scalar::from_repr_vartime(
                "0x37ba0fed1c1287a45e2e73a84f4cd378939e14753629e793ae87e1b1de1371e5"
                    .parse::<U256>()
                    .unwrap()
                    .to_little_endian()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_poseidon_hash2() {
        assert_eq!(
            poseidon_hash([34.into(), 56.into(), 78.into()]),
            Scalar::from_repr_vartime(
                "0x29c72fcb4cd2419f750991b6b93f35ec641f7c48de4db37d736bcbabb04ed4b0"
                    .parse::<U256>()
                    .unwrap()
                    .to_little_endian()
            )
            .unwrap()
        );
    }
}
