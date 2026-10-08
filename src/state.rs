//! Lineage state: the single sealed envelope for the seed, stored as a release
//! asset on the lineage release (default tag `lineage-main`).
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
//! another image, policy, or lineage fails before and during decryption.
//!
//! Report bindings (64-byte `report_data`):
//! - genesis: SHA512("zns-tee-handoff/genesis-state/v1" ‖ SHA256(blob))
//! - recovery: SHA512("zns-tee-handoff/stateless-recovery/v1" ‖ challenge ‖ SHA256(blob) ‖ fingerprint)
//!
//! Relay protocol: the guest prints the blob hex between
//! `GENESIS_STATE_BLOB_BEGIN` / `GENESIS_STATE_BLOB_END`; the operator uploads
//! it as asset `state-v1` on the lineage release. The host can omit or garble
//! the upload — it cannot fabricate one, because the report is chip-signed.

use crate::verify::{download_asset_checked, fetch_release, ReleaseSource};
use anyhow::{anyhow, ensure, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 8] = b"LNST0001";
pub const HEADER_LEN: usize = 8 + 32 + 48 + 8;
pub const NONCE_LEN: usize = 24;
pub const SEED_LEN: usize = 32;
pub const BLOB_LEN: usize = HEADER_LEN + NONCE_LEN + SEED_LEN + 16;

/// Lineage baked into the image at build time (`LINEAGE`, default `main`).
pub fn baked_lineage() -> &'static str {
    match option_env!("LINEAGE") {
        Some(lineage) if !lineage.is_empty() => lineage,
        _ => "main",
    }
}

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

/// Fetch the newest `state-vN` asset from the lineage release.
/// `Ok(None)` means the lineage release does not exist yet (fresh lineage).
pub fn fetch_latest(lineage: &str, source: &dyn ReleaseSource) -> Result<Option<Vec<u8>>> {
    let Some(release) = fetch_release(source, lineage)? else {
        return Ok(None);
    };
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| anyhow!("lineage release has no assets"))?;
    let mut latest: Option<(u32, &Value)> = None;
    for asset in assets {
        let Some(name) = asset["name"].as_str() else {
            continue;
        };
        let Some(version) = name.strip_prefix("state-v") else {
            continue;
        };
        let Ok(version) = version.parse::<u32>() else {
            continue;
        };
        if latest.as_ref().is_none_or(|(n, _)| version > *n) {
            latest = Some((version, asset));
        }
    }
    let Some((_, asset)) = latest else {
        return Err(anyhow!("lineage release has no state asset"));
    };
    Ok(Some(download_asset_checked(source, asset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{FetchError, Fetched};
    use serde_json::json;
    use std::collections::BTreeMap;

    struct Mock {
        release: Result<Value, FetchError>,
        bodies: BTreeMap<String, Vec<u8>>,
    }

    impl ReleaseSource for Mock {
        fn get(&self, url: &str, _accept: &str) -> Result<Fetched, FetchError> {
            if url.contains("/releases/tags/") {
                let body = serde_json::to_vec(&self.release.clone()?).unwrap();
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

    fn lineage_release(bodies: &BTreeMap<String, Vec<u8>>) -> Value {
        let mut assets = Vec::new();
        for (index, body) in bodies.values().enumerate() {
            assets.push(json!({
                "name": format!("state-v{}", index + 1),
                "digest": format!("sha256:{}", hex::encode(Sha256::digest(body))),
                "url": format!(
                    "https://api.github.com/repos/x/y/releases/assets/{}",
                    index + 1
                ),
            }));
        }
        json!({ "tag_name": "lineage-main", "assets": assets })
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
    fn missing_lineage_release_means_fresh() {
        let source = Mock {
            release: Err(FetchError::HttpStatus(404)),
            bodies: BTreeMap::new(),
        };
        assert!(fetch_latest("lineage-main", &source).unwrap().is_none());
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
            release: Ok(lineage_release(&bodies)),
            bodies,
        };
        let fetched = fetch_latest("lineage-main", &source).unwrap().unwrap();
        assert_eq!(fetched, blob);
    }

    #[test]
    fn tampered_state_asset_is_rejected() {
        let (blob, _, _) = sample_blob();
        let release = lineage_release(&[("1".to_string(), blob.clone())].into_iter().collect());
        let mut tampered = blob.clone();
        tampered[0] ^= 1;
        let bodies: BTreeMap<String, Vec<u8>> = [("1".to_string(), tampered)].into_iter().collect();
        let source = Mock {
            release: Ok(release),
            bodies,
        };
        let error = fetch_latest("lineage-main", &source).unwrap_err();
        assert!(error.to_string().contains("digest mismatch"));
    }
}
