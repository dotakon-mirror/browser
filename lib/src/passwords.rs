use crate::bulletproofs;
use crate::utils;
use crate::wallet::Wallet;
use anyhow::{Context, Result};
use ff::{Field, PrimeField};
use pasta_curves::{group::GroupEncoding, pallas::Point, pallas::Scalar};
use pbkdf2::pbkdf2_hmac_array;
use primitive_types::{H256, U256, U512};
use wasm_bindgen::prelude::*;

pub const K: usize = 4;
pub const MAX_PASSWORDS: usize = (1usize << K) - 1usize;

fn derive_key_impl(password: &str, salt: &[u8], num_rounds: usize) -> Scalar {
    assert!(num_rounds <= u32::MAX as usize);
    let bytes =
        pbkdf2_hmac_array::<sha3::Sha3_256, 32>(password.as_bytes(), salt, num_rounds as u32);
    utils::hash_to_scalar(&bytes)
}

#[wasm_bindgen]
pub fn derive_key(password: &str, salt: &[u8], num_rounds: usize) -> String {
    let scalar = derive_key_impl(password, salt, num_rounds);
    let scalar = U256::from_little_endian(&scalar.to_repr());
    format!("{:#x}", scalar)
}

fn encode_scalar(scalar: Scalar) -> String {
    format!("{:#x}", U256::from_little_endian(&scalar.to_repr()))
}

fn encode_point(point: &Point) -> String {
    let hex = H256::from_slice(&point.to_bytes());
    format!("{:#x}", hex)
}

fn parse_scalar(scalar: &str) -> Result<Scalar> {
    let u256: U256 = scalar.parse()?;
    Ok(Scalar::from_repr_vartime(u256.to_little_endian()).context("invalid scalar")?)
}

fn parse_point(point: &str) -> Result<Point> {
    let hex: H256 = point.parse()?;
    Ok(Point::from_bytes(hex.as_bytes().try_into().unwrap())
        .into_option()
        .context("invalid point")?)
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct PasswordSet {
    num_kdf_rounds: usize,
    salt: H256,
    seed: Scalar,
    commitment: Point,
    inner: [bulletproofs::Proof; MAX_PASSWORDS],
}

#[wasm_bindgen]
impl PasswordSet {
    fn shuffle_proofs(proofs: &mut Vec<bulletproofs::Proof>) {
        for i in 0..proofs.len() {
            let mut bytes = [0u8; 64];
            getrandom::getrandom(&mut bytes).unwrap();
            let r = U512::from_little_endian(&bytes);
            let j = r % (proofs.len() - i);
            let j = i + j.as_u64() as usize;
            proofs.swap(i, j);
        }
    }

    #[wasm_bindgen]
    pub fn create(passwords: Vec<String>, num_kdf_rounds: usize) -> Result<Self, JsValue> {
        if passwords.is_empty() {
            return Err(JsValue::from_str("no passwords specified"));
        }
        if passwords.len() > MAX_PASSWORDS {
            return Err(JsValue::from_str(
                format!("too many keys (at most {} are allowed)", MAX_PASSWORDS).as_str(),
            ));
        }
        let salt =
            utils::get_random_bytes().map_err(|_| JsValue::from_str("salt generation error"))?;
        let mut keys: Vec<Scalar> = passwords
            .iter()
            .map(|password| derive_key_impl(password.as_str(), salt.as_bytes(), num_kdf_rounds))
            .collect();
        keys.sort();
        for i in 1..keys.len() {
            if keys[i] == keys[i - 1] {
                return Err(JsValue::from_str("duplicate keys"));
            }
        }
        for _ in keys.len()..MAX_PASSWORDS {
            keys.push(
                utils::get_random_scalar()
                    .map_err(|_| JsValue::from_str("key derivation error"))?,
            );
        }
        let polynomial = bulletproofs::Polynomial::from_roots(keys.as_slice())
            .map_err(|_| JsValue::from_str("interpolation error"))?;
        let mut inner = keys
            .iter()
            .map(|key| bulletproofs::Proof::create(&polynomial, *key))
            .collect::<Result<Vec<_>>>()
            .map_err(|_| JsValue::from_str("commitment error"))?;
        Self::shuffle_proofs(&mut inner);
        Ok(Self {
            num_kdf_rounds,
            salt,
            seed: utils::get_random_scalar()
                .map_err(|_| JsValue::from_str("seed generation error"))?,
            commitment: polynomial.commitment(),
            inner: inner.try_into().unwrap(),
        })
    }

    #[wasm_bindgen]
    pub fn load(
        num_kdf_rounds: usize,
        salt: &str,
        seed: &str,
        commitment: &str,
        u: Vec<String>,
        v1: Vec<String>,
        v2: Vec<String>,
    ) -> Result<Self, JsValue> {
        if u.len() != MAX_PASSWORDS
            || v1.len() != K * 2 * MAX_PASSWORDS
            || v2.len() != K * 2 * MAX_PASSWORDS
        {
            return Err(JsValue::from_str("invalid wallet"));
        }
        let inner = (0..MAX_PASSWORDS)
            .map(|i| {
                let u = parse_scalar(u[i].as_str())?;
                let k2 = K * 2;
                let v1 = &v1[(i * k2)..((i + 1) * k2)]
                    .iter()
                    .map(|v| parse_point(v.as_str()))
                    .collect::<Result<Vec<_>>>()?;
                let v2 = &v2[(i * k2)..((i + 1) * k2)]
                    .iter()
                    .map(|v| parse_scalar(v.as_str()))
                    .collect::<Result<Vec<_>>>()?;
                let v1 = (0..K).map(|i| (v1[i * 2], v1[i * 2 + 1])).collect();
                let v2 = (0..K).map(|i| (v2[i * 2], v2[i * 2 + 1])).collect();
                Ok(bulletproofs::Proof::load(u, v1, v2))
            })
            .collect::<Result<Vec<_>>>()
            .map_err(|_| JsValue::from_str("invalid wallet"))?;
        Ok(Self {
            num_kdf_rounds,
            salt: salt
                .parse()
                .map_err(|_| JsValue::from_str("invalid salt"))?,
            seed: parse_scalar(seed).map_err(|_| JsValue::from_str("invalid seed"))?,
            commitment: parse_point(commitment).map_err(|_| JsValue::from_str("invalid wallet"))?,
            inner: inner.try_into().unwrap(),
        })
    }

    #[wasm_bindgen]
    pub fn num_kdf_rounds(&self) -> usize {
        self.num_kdf_rounds
    }

    #[wasm_bindgen]
    pub fn salt(&self) -> String {
        format!("{:#x}", self.salt)
    }

    #[wasm_bindgen]
    pub fn seed(&self) -> String {
        encode_scalar(self.seed)
    }

    #[wasm_bindgen]
    pub fn commitment(&self) -> String {
        encode_point(&self.commitment)
    }

    #[wasm_bindgen]
    pub fn u(&self) -> Vec<String> {
        self.inner
            .iter()
            .map(|proof| encode_scalar(proof.u()))
            .collect()
    }

    #[wasm_bindgen]
    pub fn v1(&self) -> Vec<String> {
        self.inner
            .iter()
            .map(|proof| {
                proof
                    .v1()
                    .iter()
                    .map(|(vl, vr)| vec![encode_point(vl), encode_point(vr)])
                    .flatten()
                    .collect::<Vec<String>>()
            })
            .flatten()
            .collect()
    }

    #[wasm_bindgen]
    pub fn v2(&self) -> Vec<String> {
        self.inner
            .iter()
            .map(|proof| {
                proof
                    .v2()
                    .iter()
                    .map(|(vl, vr)| vec![encode_scalar(*vl), encode_scalar(*vr)])
                    .flatten()
                    .collect::<Vec<String>>()
            })
            .flatten()
            .collect()
    }

    #[wasm_bindgen]
    pub fn verify(&self, password: &str) -> Result<bool, JsValue> {
        let key = derive_key_impl(password, self.salt.as_bytes(), self.num_kdf_rounds);
        for proof in &self.inner {
            if proof.verify(self.commitment, key, Scalar::ZERO).is_ok() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[wasm_bindgen]
    pub fn derive_wallet(&self, password: &str, index: usize) -> Result<Wallet, JsValue> {
        let key = derive_key_impl(password, self.salt.as_bytes(), self.num_kdf_rounds);
        for proof in &self.inner {
            if proof.verify(self.commitment, key, Scalar::ZERO).is_ok() {
                let secret_key = utils::poseidon_hash([self.seed, key, Scalar::from(index as u64)]);
                return Wallet::derive_impl(H256::from_slice(&secret_key.to_repr()));
            }
        }
        Err(JsValue::from_str("invalid password"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NUM_ROUNDS: usize = 3;

    fn salt() -> [u8; 32] {
        [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]
    }

    #[test]
    fn test_derive_key() {
        assert_eq!(
            derive_key("lorem ipsum dolor sit amet", &salt(), 100),
            "0x1f7657c1a6c42ab39b3e488a9dcb223b536cbf3267b5597d79ae8e1b57387e7b"
        );
        assert_eq!(
            derive_key("sator arepo tenet opera rotas", &salt(), NUM_ROUNDS),
            "0x373f926c4b8eaa667f7aab4e443b8762365ede8679149369ce19f140ff86dee"
        );
    }

    #[test]
    fn test_one_password() {
        let passwords = PasswordSet::create(vec!["password".into()], NUM_ROUNDS).unwrap();
        assert!(passwords.verify("password").is_ok());
        let address1 = passwords.derive_wallet("password", 0).unwrap().address();
        let address2 = passwords.derive_wallet("password", 1).unwrap().address();
        assert_ne!(address1, address2);
    }

    #[test]
    fn test_two_passwords() {
        let passwords =
            PasswordSet::create(vec!["password1".into(), "password2".into()], NUM_ROUNDS).unwrap();
        assert!(passwords.verify("password1").is_ok());
        assert!(passwords.verify("password2").is_ok());
        let address1 = passwords.derive_wallet("password1", 0).unwrap().address();
        let address2 = passwords.derive_wallet("password1", 1).unwrap().address();
        let address3 = passwords.derive_wallet("password2", 0).unwrap().address();
        let address4 = passwords.derive_wallet("password2", 1).unwrap().address();
        assert_ne!(address1, address2);
        assert_ne!(address1, address3);
        assert_ne!(address1, address4);
        assert_ne!(address2, address3);
        assert_ne!(address2, address4);
        assert_ne!(address3, address4);
    }

    #[test]
    fn test_load_password_set() {
        let passwords =
            PasswordSet::create(vec!["lorem".into(), "ipsum".into()], NUM_ROUNDS).unwrap();
        let address1 = passwords.derive_wallet("lorem", 0).unwrap().address();
        let address2 = passwords.derive_wallet("lorem", 1).unwrap().address();
        let address3 = passwords.derive_wallet("ipsum", 0).unwrap().address();
        let address4 = passwords.derive_wallet("ipsum", 1).unwrap().address();
        let (num_kdf_rounds, salt, seed, commitment, u, v1, v2) = (
            passwords.num_kdf_rounds(),
            passwords.salt(),
            passwords.seed(),
            passwords.commitment(),
            passwords.u(),
            passwords.v1(),
            passwords.v2(),
        );
        let passwords = PasswordSet::load(
            num_kdf_rounds,
            salt.as_str(),
            seed.as_str(),
            commitment.as_str(),
            u,
            v1,
            v2,
        )
        .unwrap();
        assert!(passwords.verify("lorem").is_ok());
        assert!(passwords.verify("ipsum").is_ok());
        assert_eq!(
            address1,
            passwords.derive_wallet("lorem", 0).unwrap().address()
        );
        assert_eq!(
            address2,
            passwords.derive_wallet("lorem", 1).unwrap().address()
        );
        assert_eq!(
            address3,
            passwords.derive_wallet("ipsum", 0).unwrap().address()
        );
        assert_eq!(
            address4,
            passwords.derive_wallet("ipsum", 1).unwrap().address()
        );
    }
}
