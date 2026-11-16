//! WireGuard key types.
//!
//! `SecretKey` is used for both interface private keys and peer preshared keys.
//! It zeroizes on drop, has a redacted `Debug`, and deliberately implements
//! neither `Display` nor `Serialize`, so it cannot leak through logs or IPC by
//! accident. Exposing the base64 form requires an explicit call.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a valid WireGuard key (expected 44-character base64 encoding 32 bytes)")]
pub struct InvalidKey;

fn decode_key(s: &str) -> Result<[u8; KEY_LEN], InvalidKey> {
    let s = s.trim();
    if s.len() != 44 || !s.ends_with('=') {
        return Err(InvalidKey);
    }
    let bytes = Zeroizing::new(STANDARD.decode(s).map_err(|_| InvalidKey)?);
    let mut out = [0u8; KEY_LEN];
    if bytes.len() != KEY_LEN {
        return Err(InvalidKey);
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// A public key. Not secret; safe to display, log and send to the UI.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl FromStr for PublicKey {
    type Err = InvalidKey;
    fn from_str(s: &str) -> Result<Self, InvalidKey> {
        decode_key(s).map(Self)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A private or preshared key. Zeroized on drop; never printed.
#[derive(Clone)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Generate a new random key from the operating system CSPRNG.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut k = [0u8; KEY_LEN];
        getrandom::fill(&mut k)?;
        // Clamp so the stored form matches what `wg genkey` produces.
        k[0] &= 248;
        k[31] = (k[31] & 127) | 64;
        Ok(Self(k))
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Base64 form. Only for writing to a privileged backend or an explicit,
    /// user-confirmed export. The returned string zeroizes on drop.
    pub fn expose_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.0))
    }

    pub fn expose_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive the Curve25519 public key (only meaningful for private keys).
    pub fn public_key(&self) -> PublicKey {
        let secret = x25519_dalek::StaticSecret::from(self.0);
        PublicKey(*x25519_dalek::PublicKey::from(&secret).as_bytes())
    }
}

impl FromStr for SecretKey {
    type Err = InvalidKey;
    fn from_str(s: &str) -> Result<Self, InvalidKey> {
        decode_key(s).map(Self)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        // Branch-free comparison.
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}
impl Eq for SecretKey {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7748 section 6.1 X25519 test vector (Alice), base64-encoded.
    const PRIV: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
    const PUB: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";

    #[test]
    fn derives_public_key() {
        let k: SecretKey = PRIV.parse().unwrap();
        assert_eq!(k.public_key().to_string(), PUB);
    }

    #[test]
    fn rejects_bad_keys() {
        for bad in [
            "",
            "abc",
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk",
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBm==",
            "!!!z5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk==",
        ] {
            assert!(bad.parse::<SecretKey>().is_err(), "{bad:?}");
            assert!(bad.parse::<PublicKey>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn debug_is_redacted() {
        let k: SecretKey = PRIV.parse().unwrap();
        let dbg = format!("{k:?}");
        assert!(!dbg.contains(&PRIV[..10]));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn generated_keys_roundtrip() {
        let k = SecretKey::generate().unwrap();
        let again: SecretKey = k.expose_base64().parse().unwrap();
        assert_eq!(k, again);
        assert_ne!(k, SecretKey::generate().unwrap());
    }
}
