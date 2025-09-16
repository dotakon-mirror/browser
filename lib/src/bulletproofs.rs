use crate::params;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::Field;
use pasta_curves::{group::Group, group::GroupEncoding, pallas::Point, pallas::Scalar};
use std::num::Wrapping;
use std::ops::{Add, Mul};

pub(crate) const MAX_K: u8 = 32;

/// Returns an (n, k) pair with n being the next power of 2 of x and k being its exponent.
///
/// For example, `next_power_of_two(30)` returns (32, 5).
///
/// If `x` is already a power of two, the returned n is equal to x. For example,
/// `next_power_of_two(32)` again returns (32, 5).
fn next_power_of_two(x: u64) -> (u64, u8) {
    if x == 0 {
        return (1, 0);
    }
    let mut x = Wrapping(x) - Wrapping(1u64);
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    let n = (x + Wrapping(1u64)).0;
    let k: u64 = ((n & 0xAAAAAAAAAAAAAAAA) != 0) as u64
        | (((n & 0xCCCCCCCCCCCCCCCC) != 0) as u64) << 1
        | (((n & 0xF0F0F0F0F0F0F0F0) != 0) as u64) << 2
        | (((n & 0xFF00FF00FF00FF00) != 0) as u64) << 3
        | (((n & 0xFFFF0000FFFF0000) != 0) as u64) << 4
        | (((n & 0xFFFFFFFF00000000) != 0) as u64) << 5;
    (n, k as u8)
}

fn dot<L, R>(u: &[L], v: &[R]) -> R
where
    L: Copy,
    R: Copy + Mul<L, Output = R> + Add<R, Output = R>,
{
    u.iter()
        .zip(v)
        .map(|(u, v)| *v * *u)
        .reduce(|a, b| a + b)
        .unwrap()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Polynomial {
    coefficients: Vec<Scalar>,
    commitment: Point,
}

impl Polynomial {
    pub(crate) fn from_roots(roots: &[Scalar]) -> Result<Self> {
        let mut roots = roots.to_vec();
        roots.sort();
        for i in 1..roots.len() {
            if roots[i] == roots[i - 1] {
                return Err(anyhow!("duplicate roots"));
            }
        }
        let len = roots.len() as u64;
        let (n, k) = next_power_of_two(len + 1);
        if n != len + 1 {
            return Err(anyhow!(
                "the number of roots must be a power of 2 minus 1, e.g. 255"
            ));
        }
        let n = n as usize;
        let mut coefficients = vec![Scalar::ZERO; n];
        coefficients[0] = utils::get_random_scalar()?;
        for i in 1..n {
            for j in (0..i).rev() {
                let c = coefficients[j];
                coefficients[j + 1] -= c * roots[i - 1];
            }
        }
        coefficients.reverse();
        let g = params::CACHE
            .get(k as u32)
            .get_g()
            .iter()
            .map(|g| g.into())
            .collect::<Vec<Point>>();
        let commitment = dot(coefficients.as_slice(), g.as_slice());
        Ok(Self {
            coefficients,
            commitment,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.coefficients.len()
    }

    pub(crate) fn commitment(&self) -> Point {
        self.commitment
    }

    #[cfg(test)]
    fn evaluate(&self, x: Scalar) -> Scalar {
        let mut v = Scalar::from(1);
        let mut y = Scalar::ZERO;
        for coefficient in &self.coefficients {
            y += coefficient * v;
            v *= x;
        }
        y
    }
}

#[derive(Debug)]
pub(crate) struct Proof {
    u: Scalar,
    v1: Vec<(Point, Point)>,
    v2: Vec<(Scalar, Scalar)>,
}

impl Proof {
    fn add<G: Copy + Add<Output = G>>(u: &[G], v: &[G]) -> Vec<G> {
        u.iter().zip(v).map(|(u, v)| *u + *v).collect()
    }

    fn mul<L, R>(a: L, u: &[R]) -> Vec<R>
    where
        L: Copy,
        R: Copy + Mul<L, Output = R>,
    {
        u.iter().map(|u| *u * a).collect()
    }

    pub(crate) fn create(polynomial: &Polynomial, z: Scalar) -> Result<Self> {
        let len = polynomial.len() as u64;
        let (n, k) = next_power_of_two(len);
        if n != len {
            return Err(anyhow!(
                "invalid number of polynomial coefficients (it must be a power of 2)"
            ));
        }
        let n = n as usize;
        let k = k as usize;
        let mut u = polynomial.coefficients.clone();
        let mut g = params::CACHE
            .get(k as u32)
            .get_g()
            .iter()
            .map(|g| g.into())
            .collect::<Vec<Point>>();
        let mut y = vec![Scalar::from(1); n];
        for i in 1..n {
            y[i] = y[i - 1] * z;
        }
        let mut v1 = vec![(Point::generator(), Point::generator()); k];
        let mut v2 = vec![(Scalar::ZERO, Scalar::ZERO); k];
        let seed = utils::hash_to_scalar(&polynomial.commitment.to_bytes());
        for i in (0..k).rev() {
            let n2 = 1usize << i;
            let ul = &u[0..n2];
            let ur = &u[n2..];
            let gl = &g[0..n2];
            let gr = &g[n2..];
            let yl = &y[0..n2];
            let yr = &y[n2..];
            let v1l = dot(ul, gr);
            let v1r = dot(ur, gl);
            v1[i] = (v1l, v1r);
            let v2l = dot(ul, yr);
            let v2r = dot(ur, yl);
            v2[i] = (v2l, v2r);
            let a = utils::poseidon_hash([seed, Scalar::from(i as u64)]);
            u = Self::add(
                Self::mul(a, ul).as_slice(),
                Self::mul(a.invert().unwrap(), ur).as_slice(),
            );
            g = Self::add(
                Self::mul(a.invert().unwrap(), gl).as_slice(),
                Self::mul(a, gr).as_slice(),
            );
            y = Self::add(
                Self::mul(a.invert().unwrap(), yl).as_slice(),
                Self::mul(a, yr).as_slice(),
            );
        }
        assert_eq!(u.len(), 1);
        assert_eq!(g.len(), 1);
        Ok(Self { u: u[0], v1, v2 })
    }

    pub(crate) fn load(u: Scalar, v1: Vec<(Point, Point)>, v2: Vec<(Scalar, Scalar)>) -> Self {
        assert!(v1.len() <= MAX_K as usize);
        assert_eq!(v1.len(), v2.len());
        Self { u, v1, v2 }
    }

    pub(crate) fn u(&self) -> Scalar {
        self.u
    }

    pub(crate) fn k(&self) -> u8 {
        self.v1.len() as u8
    }

    pub(crate) fn v1(&self) -> &[(Point, Point)] {
        self.v1.as_slice()
    }

    pub(crate) fn v2(&self) -> &[(Scalar, Scalar)] {
        self.v2.as_slice()
    }

    pub(crate) fn verify(&self, mut c: Point, z: Scalar, mut v: Scalar) -> Result<()> {
        let k = self.v1.len();
        let n = 1usize << k;
        let mut g = params::CACHE
            .get(k as u32)
            .get_g()
            .iter()
            .map(|g| g.into())
            .collect::<Vec<Point>>();
        let mut y = vec![Scalar::from(1); n];
        for i in 1..n {
            y[i] = y[i - 1] * z;
        }
        let seed = utils::hash_to_scalar(&c.to_bytes());
        for i in (0..k).rev() {
            let a = utils::poseidon_hash([seed, Scalar::from(i as u64)]);
            let a2 = a.square();
            let (v1l, v1r) = self.v1[i];
            c = c + v1l * a2 + v1r * a2.invert().unwrap();
            let n2 = 1usize << i;
            let gl = Self::mul(a.invert().unwrap(), &g[0..n2]);
            let gr = Self::mul(a, &g[n2..]);
            g = Self::add(gl.as_slice(), gr.as_slice());
            let yl = Self::mul(a.invert().unwrap(), &y[0..n2]);
            let yr = Self::mul(a, &y[n2..]);
            y = Self::add(yl.as_slice(), yr.as_slice());
            let (v2l, v2r) = self.v2[i];
            v = v + v2l * a2 + v2r * a2.invert().unwrap();
        }
        assert_eq!(g.len(), 1);
        assert_eq!(y.len(), 1);
        if g[0] * self.u != c || y[0] * self.u != v {
            return Err(anyhow!("invalid proof"));
        }
        Ok(())
    }

    pub(crate) fn verify_root(&self, c: Point, z: Scalar) -> Result<()> {
        self.verify(c, z, Scalar::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), (1, 0));
        assert_eq!(next_power_of_two(1), (1, 0));
        assert_eq!(next_power_of_two(2), (2, 1));
        assert_eq!(next_power_of_two(3), (4, 2));
        assert_eq!(next_power_of_two(4), (4, 2));
        assert_eq!(next_power_of_two(5), (8, 3));
        assert_eq!(next_power_of_two(6), (8, 3));
        assert_eq!(next_power_of_two(7), (8, 3));
        assert_eq!(next_power_of_two(8), (8, 3));
        assert_eq!(next_power_of_two(9), (16, 4));
        assert_eq!(next_power_of_two(10), (16, 4));
        assert_eq!(next_power_of_two(11), (16, 4));
        assert_eq!(next_power_of_two(12), (16, 4));
        assert_eq!(next_power_of_two(13), (16, 4));
        assert_eq!(next_power_of_two(14), (16, 4));
        assert_eq!(next_power_of_two(15), (16, 4));
        assert_eq!(next_power_of_two(16), (16, 4));
        assert_eq!(next_power_of_two(17), (32, 5));
        assert_eq!(next_power_of_two(18), (32, 5));
        assert_eq!(next_power_of_two(19), (32, 5));
        assert_eq!(next_power_of_two(20), (32, 5));
    }

    #[test]
    fn test_polynomial_no_roots() {
        let p = Polynomial::from_roots(&[]).unwrap();
        assert_eq!(p.len(), 1);
        assert_ne!(p.evaluate(12.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(34.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(56.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(78.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(90.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(13.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(57.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(92.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(46.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(80.into()), Scalar::ZERO);
    }

    #[test]
    fn test_polynomial_invalid_number_of_roots() {
        assert!(Polynomial::from_roots(&[12.into(), 34.into()]).is_err());
        assert!(Polynomial::from_roots(&[12.into(), 34.into(), 56.into(), 78.into()]).is_err());
        assert!(
            Polynomial::from_roots(&[12.into(), 34.into(), 56.into(), 78.into(), 90.into()])
                .is_err()
        );
        assert!(
            Polynomial::from_roots(&[
                12.into(),
                34.into(),
                56.into(),
                78.into(),
                90.into(),
                13.into()
            ])
            .is_err()
        );
    }

    #[test]
    fn test_polynomial_one_root() {
        let p = Polynomial::from_roots(&[12.into()]).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(12.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(34.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(56.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(78.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(90.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(13.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(57.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(92.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(46.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(80.into()), Scalar::ZERO);
    }

    #[test]
    fn test_polynomial_three_roots() {
        let p = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.evaluate(12.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(34.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(56.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(78.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(90.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(13.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(57.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(92.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(46.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(80.into()), Scalar::ZERO);
    }

    #[test]
    fn test_polynomial_three_roots_reverse_order() {
        let p = Polynomial::from_roots(&[56.into(), 34.into(), 12.into()]).unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.evaluate(12.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(34.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(56.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(78.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(90.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(13.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(57.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(92.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(46.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(80.into()), Scalar::ZERO);
    }

    #[test]
    fn test_polynomial_seven_roots() {
        let p = Polynomial::from_roots(&[
            12.into(),
            34.into(),
            56.into(),
            78.into(),
            90.into(),
            13.into(),
            57.into(),
        ])
        .unwrap();
        assert_eq!(p.len(), 8);
        assert_eq!(p.evaluate(12.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(34.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(56.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(78.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(90.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(13.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(57.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(92.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(46.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(80.into()), Scalar::ZERO);
    }

    #[test]
    fn test_polynomial_seven_roots_reverse_order() {
        let p = Polynomial::from_roots(&[
            57.into(),
            13.into(),
            90.into(),
            78.into(),
            56.into(),
            34.into(),
            12.into(),
        ])
        .unwrap();
        assert_eq!(p.len(), 8);
        assert_eq!(p.evaluate(12.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(34.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(56.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(78.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(90.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(13.into()), Scalar::ZERO);
        assert_eq!(p.evaluate(57.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(92.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(46.into()), Scalar::ZERO);
        assert_ne!(p.evaluate(80.into()), Scalar::ZERO);
    }

    #[test]
    fn test_polynomial_duplicate_roots() {
        assert!(
            Polynomial::from_roots(&[
                12.into(),
                34.into(),
                56.into(),
                12.into(),
                90.into(),
                12.into(),
                57.into(),
            ])
            .is_err()
        );
    }

    #[test]
    fn test_proof1() {
        let polynomial = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let proof = Proof::create(&polynomial, 12.into()).unwrap();
        assert_eq!(proof.k(), 2);
        assert!(
            proof
                .verify(polynomial.commitment(), 12.into(), Scalar::ZERO)
                .is_ok()
        );
        assert!(
            proof
                .verify(polynomial.commitment(), Scalar::ZERO, 12.into())
                .is_err()
        );
        assert!(
            proof
                .verify(polynomial.commitment(), 12.into(), 34.into())
                .is_err()
        );
        assert!(
            proof
                .verify(polynomial.commitment(), 34.into(), 12.into())
                .is_err()
        );
        assert!(
            proof
                .verify_root(polynomial.commitment(), 12.into())
                .is_ok()
        );
        assert!(
            proof
                .verify_root(polynomial.commitment(), 34.into())
                .is_err()
        );
    }

    #[test]
    fn test_proof2() {
        let polynomial = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let proof = Proof::create(&polynomial, 34.into()).unwrap();
        assert_eq!(proof.k(), 2);
        assert!(
            proof
                .verify(polynomial.commitment(), 34.into(), Scalar::ZERO)
                .is_ok()
        );
        assert!(
            proof
                .verify(polynomial.commitment(), Scalar::ZERO, 34.into())
                .is_err()
        );
        assert!(
            proof
                .verify(polynomial.commitment(), 34.into(), 12.into())
                .is_err()
        );
        assert!(
            proof
                .verify(polynomial.commitment(), 12.into(), 34.into())
                .is_err()
        );
        assert!(
            proof
                .verify_root(polynomial.commitment(), 34.into())
                .is_ok()
        );
        assert!(
            proof
                .verify_root(polynomial.commitment(), 12.into())
                .is_err()
        );
    }

    #[test]
    fn test_proof3() {
        let polynomial = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let proof = Proof::create(&polynomial, 78.into()).unwrap();
        assert_eq!(proof.k(), 2);
        assert!(
            proof
                .verify(polynomial.commitment(), 78.into(), Scalar::ZERO)
                .is_err()
        );
        assert!(
            proof
                .verify(polynomial.commitment(), 78.into(), 12.into())
                .is_err()
        );
    }
}
