use std::str::from_utf8;

use curv::{
    arithmetic::{BasicOps, Converter, Modulo, Primes, Zero},
    elliptic::curves::{Point, Scalar, Secp256k1},
    BigInt,
};
use eyre::Result;

/// An ElGamal public key using the secp256k1 curve
pub struct PubKey {
    point: Point<Secp256k1>,
}

/// An ElGamal private key using the secp256k1 curve
pub struct SecretKey {
    secret: Scalar<Secp256k1>,
}

/// An encypted ciphertext
#[derive(Debug)]
pub struct CipherText {
    c1: Point<Secp256k1>,
    c2: Point<Secp256k1>,
}

impl SecretKey {
    /// Generates a new private key using a random seed
    pub fn new() -> Self {
        Self {
            secret: Scalar::random(),
        }
    }

    /// Decryps a CipherText into a String
    pub fn decrypt_point(&self, c: &CipherText) -> Point<Secp256k1> {
        let s = self.secret.clone() * &c.c1;
        &c.c2 - s
    }

    /// Decrypts a CipherText into a String. Fails if point does not
    /// decrypt into a valid utf-8 string.
    pub fn decrypt_message(&self, c: &CipherText) -> Result<String> {
        let point = self.decrypt_point(c);
        let bytes = unembed(&point).to_bytes();
        from_utf8(&bytes)
            .map_err(|_| eyre::eyre!("cannot decode point"))
            .map(|s| s.to_string())
    }
}

impl PubKey {
    /// Encypts a Point into a CipherText
    pub fn encrypt_point(&self, m: &Point<Secp256k1>) -> CipherText {
        let r = Scalar::random();
        let c1 = r.clone() * Point::generator();
        let c2 = r * &self.point + m;

        CipherText { c1, c2 }
    }

    /// Encypts a message into a CipgerText. Fails if message is
    /// too long to fit into the curve point.
    pub fn encrypt_message(&self, m: &str) -> Result<CipherText> {
        let m = embed(&BigInt::from_bytes(m.as_bytes()))?;
        Ok(self.encrypt_point(&m))
    }
}

impl From<&SecretKey> for PubKey {
    /// Converts a private key into a public key
    fn from(sk: &SecretKey) -> Self {
        let point = sk.secret.clone() * Point::generator();
        Self { point }
    }
}

/// Encodes a BigInt message as a Point. Fails if message is too long
/// or if no valid encoding can be found the message.
/// Method based on https://arxiv.org/pdf/1707.04892.pdf
fn embed(m: &BigInt) -> Result<Point<Secp256k1>> {
    let k = 30;

    let n = BigInt::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
        .unwrap();

    if (m + 1) * k >= n {
        eyre::bail!("message too long");
    }

    for i in 0..k {
        let x = m * k + i;
        let y_squared = (x.pow(3) + 7) % n.clone();
        let y = sqrt_mod_p(&y_squared, &n)?;

        if let Some(y) = y {
            return Point::from_coords(&x, &y).map_err(|_| eyre::eyre!("cannot embed message"));
        }
    }

    Err(eyre::eyre!("cannot embed message"))
}

/// Decodes a Point into its origianl BigInt message
/// Method based on https://arxiv.org/pdf/1707.04892.pdf
fn unembed(p: &Point<Secp256k1>) -> BigInt {
    let k = 30;
    p.x_coord().unwrap() / BigInt::from(k)
}

/// Tonelli-Shanks algorithm for finding a square root in a prime field.
/// If there is no square root None is returned. Fails if p is composite.
fn sqrt_mod_p(n: &BigInt, p: &BigInt) -> Result<Option<BigInt>> {
    let ls = |x: &BigInt| -> BigInt { BigInt::mod_pow(x, &((p - 1) / 2), p) };

    if !Primes::is_probable_prime(p, 64) {
        eyre::bail!("p is composite")
    }

    if ls(n) != BigInt::from(1) {
        return Ok(None);
    }

    let mut q = p - 1;
    let mut s = BigInt::zero();

    while &q & BigInt::from(1) == BigInt::zero() {
        s += 1;
        q >>= 1;
    }

    if s == BigInt::from(1) {
        return Ok(Some(BigInt::mod_pow(n, &((p + 1) / 4), p)));
    }

    let mut z = BigInt::from(2);
    while ls(&z) != p - 1 {
        z += 1;
    }

    let mut c = BigInt::mod_pow(&z, &q, p);
    let mut r = BigInt::mod_pow(n, &((&q + 1) / 2), p);
    let mut t = BigInt::mod_pow(n, &q, p);
    let mut m = s;

    loop {
        if t == BigInt::from(1) {
            return Ok(Some(r));
        }

        let mut i = BigInt::zero();
        let mut z = t.clone();
        while z != BigInt::from(1) && i < &m - 1 {
            z = z.pow(2) % p;
            i += 1;
        }

        let mut b = c.clone();
        let e = &m - &i - 1;
        while e > BigInt::zero() {
            b = b.pow(2) % p;
        }

        r = r * &b % p;
        c = &b * &b % p;
        t = t * &c % p;
        m = i;
    }
}

#[test]
fn test_encrypt_message() {
    let sk = SecretKey::new();
    let pk = PubKey::from(&sk);

    let message = "Hello, World!".to_string();

    let enc = pk.encrypt_message(&message).unwrap();
    let message_dec = sk.decrypt_message(&enc).unwrap();

    assert_eq!(message_dec, message);
}

#[test]
fn test_encrypt_point() {
    let sk = SecretKey::new();
    let pk = PubKey::from(&sk);

    let point = Scalar::from(5) * Point::generator();

    let enc = pk.encrypt_point(&point);
    let point_dec = sk.decrypt_point(&enc);

    assert_eq!(point_dec, point);
}
