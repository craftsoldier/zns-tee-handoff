//! Dummy custody primitives. These do not authorize a release or implement handoff.
pub mod state;
pub mod verify;

use anyhow::{ensure, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip_authenticates_header() -> Result<()> {
        let key = random_secret()?;
        let header = b"test-header";
        let message = b"payload";
        let sealed = encrypt(&key, header, message)?;
        assert_eq!(&sealed[..header.len()], header);
        let opened = decrypt(&key, &sealed, header.len())?;
        assert_eq!(opened.as_slice(), message);
        Ok(())
    }

    #[test]
    fn wrong_key_and_modified_header_are_rejected() -> Result<()> {
        let key = random_secret()?;
        let wrong = random_secret()?;
        let header = b"test-header";
        let sealed = encrypt(&key, header, b"payload")?;
        assert!(decrypt(&wrong, &sealed, header.len()).is_err());
        let mut changed = sealed.clone();
        changed[0] ^= 1;
        assert!(decrypt(&key, &changed, header.len()).is_err());
        Ok(())
    }
}
