//! X-Wing (draft-connolly-cfrg-xwing-kem-06): X25519 and ML-KEM-768 combined, so a shared secret stays secret unless
//! both are broken.
use libcrux_ml_kem::mlkem768;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const PRIVATE: usize = 32;
pub const PUBLIC: usize = 1216;
pub const ENC: usize = 1120;
const MLKEM_PUBLIC: usize = 1184;
const MLKEM_CT: usize = 1088;
/// `\.//^\`.
const LABEL: &[u8; 6] = br"\.//^\";

struct Expanded {
    mlkem: mlkem768::MlKem768KeyPair,
    x25519_private: Zeroizing<[u8; 32]>,
    x25519_public: [u8; 32],
}

/// `expandDecapsulationKey`: SHAKE256 of the private key gives the ML-KEM seed `d || z` and the X25519 private key.
fn expand(private: &[u8; PRIVATE]) -> Expanded {
    let expanded = Zeroizing::new(libcrux_sha3::shake256::<96>(private));
    let mut seed = Zeroizing::new([0u8; 64]);
    seed.copy_from_slice(&expanded[..64]);
    let mlkem = mlkem768::generate_key_pair(*seed);
    let mut x25519_private = Zeroizing::new([0u8; 32]);
    x25519_private.copy_from_slice(&expanded[64..]);
    let x25519_public = x25519_dalek::x25519(*x25519_private, x25519_dalek::X25519_BASEPOINT_BYTES);
    Expanded { mlkem, x25519_private, x25519_public }
}

/// The public key of a private key: the ML-KEM-768 encapsulation key, then the X25519 public key.
pub fn public(private: &[u8; PRIVATE]) -> [u8; PUBLIC] {
    let e = expand(private);
    let mut out = [0u8; PUBLIC];
    out[..MLKEM_PUBLIC].copy_from_slice(e.mlkem.public_key().as_slice());
    out[MLKEM_PUBLIC..].copy_from_slice(&e.x25519_public);
    out
}

/// Refuses a public key whose ML-KEM half fails the FIPS 203 §7.2 modulus check.
pub fn check_public(public: &[u8; PUBLIC]) -> Result<()> {
    let mlkem: [u8; MLKEM_PUBLIC] = public[..MLKEM_PUBLIC].try_into().unwrap();
    if !mlkem768::validate_public_key(&mlkem.into()) {
        return Err(Error::Malformed("x-wing public key"));
    }
    Ok(())
}

fn combine(ss_m: &[u8; 32], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let input = Zeroizing::new([ss_m.as_slice(), ss_x, ct_x, pk_x, LABEL].concat());
    Zeroizing::new(libcrux_sha3::sha256(&input))
}

/// Encapsulates to `public` with the 64 bytes of randomness `eseed`. Returns `(enc, shared secret)`.
pub fn encapsulate(public: &[u8; PUBLIC], eseed: &[u8; 64]) -> Result<([u8; ENC], Zeroizing<[u8; 32]>)> {
    check_public(public)?;
    let pk_m: [u8; MLKEM_PUBLIC] = public[..MLKEM_PUBLIC].try_into().unwrap();
    let pk_x: [u8; 32] = public[MLKEM_PUBLIC..].try_into().unwrap();
    let mut m = Zeroizing::new([0u8; 32]);
    m.copy_from_slice(&eseed[..32]);
    let (ct_m, ss_m) = mlkem768::encapsulate(&pk_m.into(), *m);
    let ss_m = Zeroizing::new(ss_m);
    let mut ek_x = Zeroizing::new([0u8; 32]);
    ek_x.copy_from_slice(&eseed[32..]);
    let ct_x = x25519_dalek::x25519(*ek_x, x25519_dalek::X25519_BASEPOINT_BYTES);
    let ss_x = Zeroizing::new(x25519_dalek::x25519(*ek_x, pk_x));
    let mut enc = [0u8; ENC];
    enc[..MLKEM_CT].copy_from_slice(ct_m.as_slice());
    enc[MLKEM_CT..].copy_from_slice(&ct_x);
    Ok((enc, combine(&ss_m, &ss_x, &ct_x, &pk_x)))
}

/// Decapsulates `enc` with `private`.
pub fn decapsulate(private: &[u8; PRIVATE], enc: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let enc: &[u8; ENC] = enc.try_into().map_err(|_| Error::Decrypt)?;
    let e = expand(private);
    let ct_m: [u8; MLKEM_CT] = enc[..MLKEM_CT].try_into().unwrap();
    let ct_x: [u8; 32] = enc[MLKEM_CT..].try_into().unwrap();
    let ss_m = Zeroizing::new(mlkem768::decapsulate(e.mlkem.private_key(), &ct_m.into()));
    // As the draft specifies, no low-order check: ML-KEM keeps the combined secret unpredictable.
    let ss_x = Zeroizing::new(x25519_dalek::x25519(*e.x25519_private, ct_x));
    Ok(combine(&ss_m, &ss_x, &ct_x, &e.x25519_public))
}
