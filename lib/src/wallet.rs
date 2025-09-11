use curve25519_dalek::{EdwardsPoint as Point25519, Scalar as Scalar25519};
use ff::{FromUniformBytes, PrimeField};
use getrandom::getrandom;
use pasta_curves::{
    self,
    group::{Group, GroupEncoding},
    pallas::{Point as PointPallas, Scalar as ScalarPallas},
};
use primitive_types::{H256, U256};
use sha3::{self, Digest};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Wallet {
    private_key_c25519: Scalar25519,
    public_key_c25519: Point25519,
    private_key_pallas: ScalarPallas,
    public_key_pallas: PointPallas,
    address: ScalarPallas,
}

#[wasm_bindgen]
impl Wallet {
    fn hash_to_pallas_scalar(value: H256) -> ScalarPallas {
        let mut hasher = sha3::Sha3_512::new();
        hasher.update(value.to_fixed_bytes());
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(hasher.finalize().as_slice());
        ScalarPallas::from_uniform_bytes(&bytes)
    }

    fn compress_point_c25519(point: &Point25519) -> H256 {
        H256::from_slice(&point.compress().to_bytes())
    }

    fn compress_point_pallas(point: &PointPallas) -> H256 {
        H256::from_slice(&point.to_bytes())
    }

    pub fn derive_new() -> Result<Self, JsValue> {
        let mut secret_key = [0u8; 32];
        getrandom(&mut secret_key)
            .map_err(|_| JsValue::from_str("error generating a random key"))?;
        let secret_key = H256::from_slice(&secret_key);

        let ed25519_signing_key =
            ed25519_dalek::SigningKey::from_bytes(&secret_key.to_fixed_bytes());

        let private_key_c25519 = ed25519_signing_key.to_scalar();
        let private_key_pallas =
            ScalarPallas::from_repr_vartime(private_key_c25519.to_bytes()).unwrap();

        let public_key_pallas = PointPallas::generator() * private_key_pallas;
        let public_key_c25519 = Point25519::mul_base(&private_key_c25519);

        let address = Self::hash_to_pallas_scalar(Self::compress_point_pallas(&public_key_pallas));

        Ok(Self {
            private_key_c25519,
            public_key_c25519,
            private_key_pallas,
            public_key_pallas,
            address,
        })
    }

    pub fn public_key_c25519(&self) -> String {
        format!(
            "{:#x}",
            Self::compress_point_c25519(&self.public_key_c25519)
        )
    }

    pub fn public_key_pallas(&self) -> String {
        format!(
            "{:#x}",
            Self::compress_point_pallas(&self.public_key_pallas)
        )
    }

    pub fn address(&self) -> String {
        format!("{:#x}", U256::from_little_endian(&self.address.to_repr()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
