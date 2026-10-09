//! Seeded custody state: the single sealed envelope for the seed. Since
//! immutable releases, each state version is its own release — tag
//! `custody-vN`, single asset `state` — so the release history is the
//! chain of custody.
//!
//! Wire format — the header is also the AEAD additional authenticated data:
//! ```text
//! MAGIC        8   b"LNST001"
//! fingerprint  32  SHA-256 of the seed
//! measurement  48  launch measurement of the sealing image
//! policy       8   guest policy, u64 little-endian
//! nonce        24  XChaCha20-Poly1305 nonce
//! ciphertext   48  seed (32) + tag (16)
//! ```
//! Total 168 bytes. Opening requires the chip-derived key of the same chip,
//! measurement, and policy; the header is authenticated, so a blob from
//! another image, policy, or chip fails before and during decryption.
//!
//! Report bindings (64-byte `report_data`):
//! - genesis: SHA512("zns-tee-handoff/genesis-state/v1" ‖ SHA256(blob))
//! - recovery: SHA512("zns-tee-handoff/stateless-recovery/v1" ‖ challenge ‖ SHA256(blob) ‖ fingerprint)
//!
//! Relay protocol: the guest prints the blob hex between
//! `GENESIS_STATE_BLOB_BEGIN` / `GENESIS_STATE_BLOB_END`; the operator uploads
//! it as asset `state` on the `custody-v1` release. The host can omit or garble
//! the upload — it cannot fabricate one, because the report is chip-signed.

use crate::verify::{download_asset_checked, ReleaseSource};
use anyhow::{anyhow, ensure, Result};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

pub const MAGIC: &[u8; 8] = b"LNST0001";
pub const ANNOUNCE_DOMAIN: &[u8] = b"zns-tee-handoff/announce/v1";
pub const WRAP_DOMAIN: &[u8] = b"zns-tee-handoff/migration-wrap/v1";
pub const HEADER_LEN: usize = 8 + 32 + 48 + 8;
pub const NONCE_LEN: usize = 24;
pub const SEED_LEN: usize = 32;
pub const BLOB_LEN: usize = HEADER_LEN + NONCE_LEN + SEED_LEN + 16;

/// Seal the seed under the caller's chip-derived key. One envelope, one key.
pub fn seal(
    chip_key: &[u8; 32],
    seed: &[u8; 32],
    measurement: &[u8; 48],
    policy: u64,
) -> Result<Vec<u8>> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&Sha256::digest(seed));
    header.extend_from_slice(measurement);
    header.extend_from_slice(&policy.to_le_bytes());
    crate::encrypt(chip_key, &header, seed)
}

/// Open the envelope. Rejects wrong chip keys, other images/policies, and
/// every modified byte.
pub fn open(chip_key: &[u8; 32], blob: &[u8]) -> Result<[u8; SEED_LEN]> {
    ensure!(
        blob.len() == BLOB_LEN && &blob[..8] == MAGIC,
        "invalid state blob"
    );
    let seed = crate::decrypt(chip_key, blob, HEADER_LEN)?;
    ensure!(seed.len() == SEED_LEN, "invalid state payload");
    let mut out = [0u8; SEED_LEN];
    out.copy_from_slice(&seed);
    ensure!(
        Sha256::digest(out).as_slice() == &blob[8..40],
        "seed fingerprint mismatch"
    );
    Ok(out)
}

/// Sealing measurement field of a state blob (bytes 40..88): which image
/// generation the seed is currently sealed for.
pub fn blob_measurement(blob: &[u8]) -> Result<[u8; 48]> {
    ensure!(
        blob.len() == BLOB_LEN && &blob[..8] == MAGIC,
        "invalid state blob"
    );
    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(&blob[40..88]);
    Ok(measurement)
}

/// Public fingerprint field of a state blob (bytes 8..40).
pub fn fingerprint_of(blob: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        blob.len() == BLOB_LEN && &blob[..8] == MAGIC,
        "invalid state blob"
    );
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&blob[8..40]);
    Ok(fingerprint)
}

/// Fetch the newest custody state. Since immutable releases, each state
/// version is its own release: tag `custody-vN`, single asset `state`.
/// `Ok(None)` means no custody release exists yet (fresh seed).
pub fn fetch_custody_state(source: &dyn ReleaseSource) -> Result<Option<Vec<u8>>> {
    let releases = crate::verify::fetch_release_list(source)?;
    let mut latest: Option<(u32, &Value)> = None;
    for release in &releases {
        let Some(tag) = release["tag_name"].as_str() else {
            continue;
        };
        let Some(version) = tag.strip_prefix("custody-v") else {
            continue;
        };
        let Ok(version) = version.parse::<u32>() else {
            continue;
        };
        if latest.as_ref().is_none_or(|(n, _)| version > *n) {
            latest = Some((version, release));
        }
    }
    let Some((_, release)) = latest else {
        return Ok(None);
    };
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| anyhow!("state release has no assets"))?;
    let asset = assets
        .iter()
        .find(|a| a["name"].as_str() == Some("state"))
        .ok_or_else(|| anyhow!("state release has no state asset"))?;
    Ok(Some(download_asset_checked(source, asset)?))
}

/// The announcement a successor publishes inside its own release:
/// its ECIES public key (SEC1 uncompressed) plus a report binding that key
/// to the successor's measurement (`report_data` = `announcement_report_data`).
pub struct Announcement {
    pub pubkey: Vec<u8>,
    pub report: Vec<u8>,
}

/// Expected `report_data` for a successor announcement.
pub fn announcement_report_data(pubkey_sec1: &[u8]) -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update(ANNOUNCE_DOMAIN);
    hash.update(Sha256::digest(pubkey_sec1));
    hash.finalize().into()
}

/// ECIES wrap: ephemeral key `E`, seed encrypted under HKDF(e·Q),
/// header (also the AAD) binding the fingerprint, `Q`, and `E`.
pub struct WrapOutput {
    pub ephemeral_pubkey: Vec<u8>,
    pub blob: Vec<u8>,
}

pub const WRAP_MAGIC: &[u8; 8] = b"MIGW0001";
pub const WRAP_HEADER_LEN: usize = 8 + 32 + 32 + 32;

/// Custodian side: seal the seed for the successor's announced key.
pub fn wrap_seed(
    seed: &[u8; 32],
    fingerprint: &[u8; 32],
    peer_pubkey_sec1: &[u8],
) -> Result<WrapOutput> {
    use p256::elliptic_curve::ecdh::diffie_hellman;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::{PublicKey, SecretKey};

    let peer = PublicKey::from_sec1_bytes(peer_pubkey_sec1)
        .map_err(|_| anyhow!("invalid successor pubkey"))?;
    let ephemeral = SecretKey::random(&mut rand::rngs::OsRng);
    let shared = diffie_hellman(&ephemeral.to_nonzero_scalar(), peer.as_affine());
    let ephemeral_pubkey = ephemeral.public_key().to_encoded_point(false);

    let mut header = Vec::with_capacity(WRAP_HEADER_LEN);
    header.extend_from_slice(WRAP_MAGIC);
    header.extend_from_slice(fingerprint);
    header.extend_from_slice(&Sha256::digest(peer_pubkey_sec1));
    header.extend_from_slice(&Sha256::digest(ephemeral_pubkey.as_bytes()));
    let mut wrap_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared.raw_secret_bytes())
        .expand(WRAP_DOMAIN, &mut wrap_key)
        .map_err(|_| anyhow!("wrap key derivation failed"))?;
    let blob = crate::encrypt(&wrap_key, &header, seed)?;
    Ok(WrapOutput {
        ephemeral_pubkey: ephemeral_pubkey.as_bytes().to_vec(),
        blob,
    })
}

/// Successor side: open the wrap with the announced private key.
pub fn unwrap_seed(
    recipient: &p256::SecretKey,
    ephemeral_pubkey_sec1: &[u8],
    blob: &[u8],
) -> Result<[u8; SEED_LEN]> {
    use p256::elliptic_curve::ecdh::diffie_hellman;
    use p256::PublicKey;

    ensure!(
        blob.len() == WRAP_HEADER_LEN + NONCE_LEN + SEED_LEN + 16,
        "invalid wrap blob"
    );
    ensure!(&blob[..8] == WRAP_MAGIC, "invalid wrap blob magic");
    let ephemeral = PublicKey::from_sec1_bytes(ephemeral_pubkey_sec1)
        .map_err(|_| anyhow!("invalid ephemeral pubkey"))?;
    let shared = diffie_hellman(&recipient.to_nonzero_scalar(), ephemeral.as_affine());
    let mut wrap_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared.raw_secret_bytes())
        .expand(WRAP_DOMAIN, &mut wrap_key)
        .map_err(|_| anyhow!("wrap key derivation failed"))?;
    let seed = crate::decrypt(&wrap_key, blob, WRAP_HEADER_LEN)?;
    ensure!(seed.len() == SEED_LEN, "invalid wrapped payload");
    let mut out = [0u8; SEED_LEN];
    out.copy_from_slice(&seed);
    ensure!(
        Sha256::digest(out).as_slice() == &blob[8..40],
        "wrapped seed fingerprint mismatch"
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{FetchError, Fetched};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    use serde_json::json;
    use std::collections::BTreeMap;

    struct Mock {
        releases: Result<Value, FetchError>,
        bodies: BTreeMap<String, Vec<u8>>,
    }

    impl Mock {
        fn releases(bodies: &BTreeMap<String, Vec<u8>>) -> Value {
            let mut releases = Vec::new();
            for (index, body) in bodies.values().enumerate() {
                releases.push(json!({
                    "tag_name": format!("custody-v{}", index + 1),
                    "assets": [{
                        "name": "state",
                        "digest": format!("sha256:{}", hex::encode(Sha256::digest(body))),
                        "url": format!(
                            "https://api.github.com/repos/x/y/releases/assets/{}",
                            index + 1
                        ),
                    }],
                }));
            }
            json!(releases)
        }
    }

    impl ReleaseSource for Mock {
        fn get(&self, url: &str, _accept: &str) -> Result<Fetched, FetchError> {
            if url.ends_with("/releases") {
                let body = serde_json::to_vec(&self.releases.clone()?).unwrap();
                return Ok(Fetched {
                    body,
                    final_url: url.to_string(),
                });
            }
            if url.contains("/releases/assets/") {
                let id = url.rsplit('/').next().unwrap_or_default().to_string();
                let body = self
                    .bodies
                    .get(&id)
                    .cloned()
                    .ok_or(FetchError::HttpStatus(404))?;
                return Ok(Fetched {
                    body,
                    final_url: "https://objects.githubusercontent.com/blob".to_string(),
                });
            }
            Err(FetchError::HttpStatus(500))
        }
    }

    fn sample_blob() -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let chip_key = [7u8; 32];
        let seed = [9u8; 32];
        let blob = seal(&chip_key, &seed, &[3u8; 48], 0x30000).unwrap();
        (blob, chip_key, seed)
    }

    #[test]
    fn seal_open_roundtrip() {
        let (blob, chip_key, seed) = sample_blob();
        assert_eq!(blob.len(), BLOB_LEN);
        assert_eq!(open(&chip_key, &blob).unwrap(), seed);
    }

    #[test]
    fn wrong_chip_key_is_rejected() {
        let (blob, _, _) = sample_blob();
        assert!(open(&[8u8; 32], &blob).is_err());
    }

    #[test]
    fn every_modified_byte_is_rejected() {
        let (blob, chip_key, _) = sample_blob();
        for offset in 0..blob.len() {
            let mut changed = blob.clone();
            changed[offset] ^= 1;
            assert!(open(&chip_key, &changed).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn fingerprint_field_matches_seed() {
        let (blob, _, seed) = sample_blob();
        assert_eq!(
            fingerprint_of(&blob).unwrap(),
            Sha256::digest(seed).as_slice()
        );
    }

    #[test]
    fn missing_state_means_fresh() {
        let source = Mock {
            releases: Ok(json!([])),
            bodies: BTreeMap::new(),
        };
        assert!(fetch_custody_state(&source).unwrap().is_none());
    }

    #[test]
    fn fetch_picks_the_highest_version() {
        let (blob, _, _) = sample_blob();
        let bodies: BTreeMap<String, Vec<u8>> = [
            ("1".to_string(), blob.clone()),
            ("2".to_string(), blob.clone()),
        ]
        .into_iter()
        .collect();
        let source = Mock {
            releases: Ok(Mock::releases(&bodies)),
            bodies,
        };
        let fetched = fetch_custody_state(&source).unwrap().unwrap();
        assert_eq!(fetched, blob);
    }

    #[test]
    fn tampered_state_asset_is_rejected() {
        let (blob, _, _) = sample_blob();
        let release = Mock::releases(&[("1".to_string(), blob.clone())].into_iter().collect());
        let mut tampered = blob.clone();
        tampered[0] ^= 1;
        let bodies: BTreeMap<String, Vec<u8>> = [("1".to_string(), tampered)].into_iter().collect();
        let source = Mock {
            releases: Ok(release),
            bodies,
        };
        let error = fetch_custody_state(&source).unwrap_err();
        assert!(error.to_string().contains("digest mismatch"));
    }

    #[test]
    fn ecies_wrap_unwrap_roundtrip() {
        let recipient = SecretKey::random(&mut rand::rngs::OsRng);
        let seed = [11u8; 32];
        let fingerprint: [u8; 32] = Sha256::digest(seed).into();
        let q = recipient.public_key().to_encoded_point(false);
        let wrap = wrap_seed(&seed, &fingerprint, q.as_bytes()).unwrap();
        let opened = unwrap_seed(&recipient, &wrap.ephemeral_pubkey, &wrap.blob).unwrap();
        assert_eq!(opened, seed);
    }

    #[test]
    fn wrap_decryption_with_wrong_key_is_rejected() {
        let recipient = SecretKey::random(&mut rand::rngs::OsRng);
        let outsider = SecretKey::random(&mut rand::rngs::OsRng);
        let seed = [11u8; 32];
        let fingerprint: [u8; 32] = Sha256::digest(seed).into();
        let q = recipient.public_key().to_encoded_point(false);
        let wrap = wrap_seed(&seed, &fingerprint, q.as_bytes()).unwrap();
        assert!(unwrap_seed(&outsider, &wrap.ephemeral_pubkey, &wrap.blob).is_err());
    }

    #[test]
    fn tampered_wrap_blob_is_rejected() {
        let recipient = SecretKey::random(&mut rand::rngs::OsRng);
        let seed = [11u8; 32];
        let fingerprint: [u8; 32] = Sha256::digest(seed).into();
        let q = recipient.public_key().to_encoded_point(false);
        let mut wrap = wrap_seed(&seed, &fingerprint, q.as_bytes()).unwrap();
        let last = wrap.blob.len() - 1;
        wrap.blob[last] ^= 1;
        assert!(unwrap_seed(&recipient, &wrap.ephemeral_pubkey, &wrap.blob).is_err());
    }
}
