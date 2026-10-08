//! Dummy custody primitives. These do not authorize a release or implement handoff.
pub mod verify;
use anyhow::{bail, ensure, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"DHCAP001";
pub const CAPSULE_LEN: usize = 8 + 32 + 24 + 32 + 16;

pub fn random_secret() -> Result<Zeroizing<[u8; 32]>> {
    let mut bytes = Zeroizing::new([0; 32]);
    OsRng.try_fill_bytes(bytes.as_mut())?;
    Ok(bytes)
}

pub fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Encrypt under a fresh 192-bit public nonce, authenticating the entire header.
pub fn encrypt(key: &[u8; 32], header: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0; 24];
    OsRng.try_fill_bytes(&mut nonce)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: header,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let mut output = header.to_vec();
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(key: &[u8; 32], bytes: &[u8], header_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        bytes.len() >= header_len.saturating_add(24 + 16),
        "truncated encrypted record"
    );
    let plaintext = XChaCha20Poly1305::new(key.into())
        .decrypt(
            XNonce::from_slice(&bytes[header_len..header_len + 24]),
            Payload {
                msg: &bytes[header_len + 24..],
                aad: &bytes[..header_len],
            },
        )
        .map_err(|_| anyhow::anyhow!("record authentication failed"))?;
    Ok(Zeroizing::new(plaintext))
}

pub struct Genesis {
    pub sk: Zeroizing<[u8; 32]>,
    pub capsule: Vec<u8>,
    pub fingerprint: [u8; 32],
}

impl Genesis {
    pub fn generate() -> Result<Self> {
        let seed = random_secret()?;
        let sk = random_secret()?;
        let fingerprint = hash(seed.as_ref());
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&fingerprint);
        let capsule = encrypt(&sk, &header, seed.as_ref())?;
        // `seed` is zeroized here. SK stays inside the owner until drop.
        Ok(Self {
            sk,
            capsule,
            fingerprint,
        })
    }
}

pub fn open_capsule(sk: &[u8; 32], capsule: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        capsule.len() == CAPSULE_LEN && &capsule[..8] == MAGIC,
        "invalid capsule format"
    );
    let plaintext = decrypt(sk, capsule, 40)?;
    if plaintext.len() != 32 || hash(&plaintext) != capsule[8..40] {
        bail!("seed fingerprint mismatch");
    }
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_seed_matches_public_fingerprint() -> Result<()> {
        let genesis = Genesis::generate()?;
        let seed = open_capsule(&genesis.sk, &genesis.capsule)?;
        assert_eq!(hash(seed.as_ref()), genesis.fingerprint);
        assert_eq!(genesis.capsule.len(), CAPSULE_LEN);
        Ok(())
    }

    #[test]
    fn wrong_key_and_every_modified_byte_are_rejected() -> Result<()> {
        let genesis = Genesis::generate()?;
        let wrong_key = random_secret()?;
        assert!(open_capsule(&wrong_key, &genesis.capsule).is_err());
        for offset in 0..genesis.capsule.len() {
            let mut changed = genesis.capsule.clone();
            changed[offset] ^= 1;
            assert!(
                open_capsule(&genesis.sk, &changed).is_err(),
                "offset {offset}"
            );
        }
        for length in 0..genesis.capsule.len() {
            assert!(open_capsule(&genesis.sk, &genesis.capsule[..length]).is_err());
        }
        Ok(())
    }

    #[test]
    fn chip_wrapping_header_and_capsule_identity_are_authenticated() -> Result<()> {
        let wrapping_key = random_secret()?;
        let sk = random_secret()?;
        let record = encrypt(&wrapping_key, b"chip-and-capsule-context", sk.as_ref())?;
        assert_eq!(decrypt(&wrapping_key, &record, 24)?.as_slice(), sk.as_ref());
        let mut changed = record;
        changed[0] ^= 1;
        assert!(decrypt(&wrapping_key, &changed, 24).is_err());
        Ok(())
    }
}
