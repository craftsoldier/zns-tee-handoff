//! Stateless seeded boot plus the M0→M1 handoff seam.
//!
//! Roles are selected by the baked release tag:
//! - `m0-v*` (custodian): fetch-or-create the custody state, then listen on
//!   the console for `HANDOFF <m1-tag>` and wrap the seed for the successor
//!   announced inside that release.
//! - `m1-v*` (successor): announce an ephemeral ECIES key on the console and
//!   wait for the wrap; re-seal the seed under this image's own measurement.
//!
//! Everything crossing the console is either chip-signed (reports) or
//! ciphertext to a key whose announcement was pinned by an immutable GitHub
//! release. The relay can censor or garble; it cannot forge.
use anyhow::{ensure, Context, Result};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use sev::{
    firmware::guest::{AttestationReport, DerivedKey, Firmware, GuestFieldSelect},
    parser::ByteParser,
};
use sha2::{Digest, Sha256, Sha512};
use std::{
    io::BufRead,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
use zns_tee_handoff::{hash, random_secret, state, verify};

const POLICY: u64 = 0x30000;
const HANDOFF_WAIT: Duration = Duration::from_secs(3600);

pub fn live_measurement() -> Result<[u8; 48]> {
    let mut firmware = Firmware::open().context("open /dev/sev-guest")?;
    let raw = firmware.get_report(Some(1), Some([0; 64]), Some(0))?;
    let report = AttestationReport::from_bytes(&raw)?;
    ensure!(report.measurement != [0; 48], "missing launch measurement");
    Ok(report.measurement)
}

/// Chip-derived sealing key: hardware root key narrowed to this guest's
/// policy and measurement, then HKDF-separated. Re-derivable only by this
/// physical chip for this measured image under this policy.
fn chip_key(firmware: &mut Firmware) -> Result<Zeroizing<[u8; 32]>> {
    let mut fields = GuestFieldSelect::default();
    fields.set_guest_policy(true);
    fields.set_measurement(true);
    let request = DerivedKey::new(false, fields, 0, 0, 0, None);
    let raw = Zeroizing::new(firmware.get_derived_key(Some(1), request)?);
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, raw.as_ref())
        .expand(b"zns-tee-handoff/state-seal/v1", key.as_mut())
        .map_err(|_| anyhow::anyhow!("state key derivation failed"))?;
    Ok(key)
}

fn is_successor() -> bool {
    verify::baked_tag().is_some_and(|tag| tag.starts_with("m1-v"))
}

/// Fetch or create the custody state, then — as custodian — listen for a
/// handoff trigger on the console. Non-fatal: a timeout simply leaves this
/// image as the standing custodian.
pub fn boot(challenge: [u8; 32]) -> Result<()> {
    let source = verify::GitHubRelease::default();
    let mut firmware =
        Firmware::open().context("open /dev/sev-guest; run inside a dedicated SNP test guest")?;
    let chip_key = chip_key(&mut firmware)?;
    let measurement = live_measurement()?;
    match state::fetch_custody_state(&source)? {
        // Fresh lineage: the custodian creates the seed; a successor waits.
        None => {
            if is_successor() {
                successor_boot(&mut firmware, &chip_key)?;
            } else {
                genesis_state(&mut firmware, &chip_key)?;
            }
        }
        Some(blob) => {
            let sealed_for = state::blob_measurement(&blob)?;
            if sealed_for == measurement {
                // This generation holds custody: recover, then offer handoff.
                let seed = state::open(&chip_key, &blob)?;
                recover_state(&mut firmware, &blob, &seed, challenge)?;
                println!("M0_TEST_COMPLETE: custody recovered; handoff listening on console");
                if !is_successor() {
                    handoff_listen(&seed, &source)?;
                }
            } else if is_successor() {
                // The current state is sealed for a different generation:
                // announce and take custody.
                successor_boot(&mut firmware, &chip_key)?;
            } else {
                println!(
                    "m0_stand_down=ok; custody is held by a newer generation; \
                     this image remains bootable for recovery and handoff"
                );
            }
        }
    }
    release_self_check();
    Ok(())
}

fn genesis_state(firmware: &mut Firmware, chip_key: &[u8; 32]) -> Result<()> {
    let seed = random_secret()?;
    let measurement = live_measurement()?;
    let blob = state::seal(chip_key, &seed, &measurement, POLICY)?;
    let mut binding = Sha512::new();
    binding.update(b"zns-tee-handoff/genesis-state/v1");
    binding.update(Sha256::digest(&blob));
    let report = firmware.get_report(Some(1), Some(binding.finalize().into()), Some(0))?;
    println!("GENESIS_STATE_BLOB_BEGIN");
    println!("{}", hex::encode(&blob));
    println!("GENESIS_STATE_BLOB_END");
    println!("custody_state_sha256={}", hex::encode(hash(&blob)));
    println!("dummy_seed_sha256={}", hex::encode(hash(&seed[..])));
    println!("genesis_report_hex={}", hex::encode(&report));
    println!(
        "m0_state_created=ok; sealed to this chip, measurement, and policy; \
         relay the blob to a custody-v1 release"
    );
    Ok(())
}

fn recover_state(
    firmware: &mut Firmware,
    blob: &[u8],
    seed: &[u8; 32],
    challenge: [u8; 32],
) -> Result<()> {
    let fingerprint = hash(seed);
    let mut binding = Sha512::new();
    binding.update(b"zns-tee-handoff/stateless-recovery/v1");
    binding.update(challenge);
    binding.update(Sha256::digest(blob));
    binding.update(fingerprint);
    let report = firmware.get_report(Some(1), Some(binding.finalize().into()), Some(0))?;
    println!("dummy_seed_sha256={}", hex::encode(fingerprint));
    println!("custody_state_sha256={}", hex::encode(hash(blob)));
    println!("recovery_challenge={}", hex::encode(challenge));
    println!("recovery_report_hex={}", hex::encode(&report));
    println!("state_recovered=ok; state fetched from the custody release");
    Ok(())
}

/// Custodian side of the seam: wait for `HANDOFF <m1-tag>` on the console,
/// verify the successor announcement published inside that release, then
/// print the ECIES-wrapped seed. Censorship or garbage leaves custody
/// unchanged; M0 remains the standing custodian and can retry forever.
fn handoff_listen(seed: &[u8; 32], source: &verify::GitHubRelease) -> Result<()> {
    println!("m0_handoff_listening=ok; write HANDOFF <m1-tag> on the console");
    let (sender, receiver) = mpsc::channel::<String>();
    thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { return };
            if sender.send(line).is_err() {
                return;
            }
        }
    });

    let deadline = Instant::now() + HANDOFF_WAIT;
    let mut successor_tag = None;
    while Instant::now() < deadline {
        let Ok(line) = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        else {
            break;
        };
        if let Some(tag) = line.strip_prefix("HANDOFF ") {
            require(tag.starts_with("m1-v"), "successor tag must match m1-v*")?;
            successor_tag = Some(tag.to_string());
            break;
        }
    }
    let Some(successor_tag) = successor_tag else {
        println!("m0_handoff_timeout=ok; remaining standing custodian");
        return Ok(());
    };

    let release = verify::fetch_release(source, &successor_tag)?
        .ok_or_else(|| anyhow::anyhow!("successor release not found"))?;
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("successor release has no assets"))?;
    let find = |name: &str| {
        assets
            .iter()
            .find(|a| a["name"].as_str() == Some(name))
            .ok_or_else(|| anyhow::anyhow!("successor release missing {name}"))
    };
    let measurement_asset = find("snp-measurement.txt")?;
    let announce_asset = find("announcement.txt")?;
    let measurement_bytes = verify::download_asset_checked(source, measurement_asset)?;
    let announcement_bytes = verify::download_asset_checked(source, announce_asset)?;

    let measurement_text = std::str::from_utf8(&measurement_bytes)?.trim();
    ensure!(
        measurement_text.len() == 96,
        "malformed successor measurement"
    );
    let mut measurement = [0u8; 48];
    hex::decode_to_slice(measurement_text, &mut measurement)?;

    let mut pubkey = None;
    let mut report = None;
    for line in String::from_utf8(announcement_bytes)?.lines() {
        if let Some(value) = line.strip_prefix("pubkey=") {
            pubkey = Some(hex::decode(value)?);
        }
        if let Some(value) = line.strip_prefix("report=") {
            report = Some(hex::decode(value)?);
        }
    }
    let pubkey = pubkey.ok_or_else(|| anyhow::anyhow!("announcement has no pubkey"))?;
    let report = report.ok_or_else(|| anyhow::anyhow!("announcement has no report"))?;

    let report = AttestationReport::from_bytes(&report)?;
    ensure!(
        report.measurement == measurement,
        "announcement report does not match the successor release measurement"
    );
    ensure!(report.policy.0 == POLICY, "announcement policy mismatch");
    ensure!(
        report.report_data == state::announcement_report_data(&pubkey),
        "announcement report does not bind the successor pubkey"
    );

    let fingerprint = hash(seed);
    let wrap = state::wrap_seed(seed, &fingerprint, &pubkey)?;
    println!("WRAP_BEGIN");
    println!("ephemeral_pubkey={}", hex::encode(&wrap.ephemeral_pubkey));
    println!("blob={}", hex::encode(&wrap.blob));
    println!("WRAP_END");
    println!("m0_handoff_complete=ok; seed wrapped for the successor announced in {successor_tag}");
    Ok(())
}

/// Successor side of the seam: announce an ephemeral key, wait for the wrap,
/// re-seal the seed under this image's own measurement.
fn successor_boot(firmware: &mut Firmware, chip_key: &[u8; 32]) -> Result<()> {
    let secret = SecretKey::random(&mut rand::rngs::OsRng);
    let pubkey = secret.public_key().to_encoded_point(false);
    let binding = state::announcement_report_data(pubkey.as_bytes());
    let report = firmware.get_report(Some(1), Some(binding), Some(0))?;
    println!("ANNOUNCE_BEGIN");
    println!("pubkey={}", hex::encode(pubkey.as_bytes()));
    println!("report={}", hex::encode(&report));
    println!("ANNOUNCE_END");
    println!("m1_announced=ok; waiting for the handoff wrap on the console");

    let stdin = std::io::stdin();
    let (ephemeral_pubkey, wrap_blob) = read_wrap_block(&mut stdin.lock())?;
    let seed = state::unwrap_seed(&secret, &ephemeral_pubkey, &wrap_blob)?;
    let fingerprint = hash(&seed);
    let measurement = live_measurement()?;
    let blob = state::seal(chip_key, &seed, &measurement, POLICY)?;
    println!("CUSTODY_STATE_BLOB_BEGIN");
    println!("{}", hex::encode(&blob));
    println!("CUSTODY_STATE_BLOB_END");
    println!("dummy_seed_sha256={}", hex::encode(fingerprint));
    println!(
        "m1_custody_taken=ok; seed re-sealed under this image's measurement; \
         relay the blob to a custody-v2 release"
    );
    Ok(())
}

fn read_wrap_block(stdin: &mut impl BufRead) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut ephemeral_pubkey = None;
    let mut blob = None;
    let mut inside = false;
    for line in stdin.lines() {
        let line = line?;
        if line == "WRAP_BEGIN" {
            inside = true;
            continue;
        }
        if inside {
            if line == "WRAP_END" {
                break;
            }
            if let Some(value) = line.strip_prefix("ephemeral_pubkey=") {
                ephemeral_pubkey = Some(hex::decode(value)?);
            }
            if let Some(value) = line.strip_prefix("blob=") {
                blob = Some(hex::decode(value)?);
            }
        }
    }
    let Some(ephemeral_pubkey) = ephemeral_pubkey else {
        anyhow::bail!("wrap block missing ephemeral_pubkey");
    };
    let Some(blob) = blob else {
        anyhow::bail!("wrap block missing blob");
    };
    Ok((ephemeral_pubkey, blob))
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        anyhow::bail!("{message}")
    }
}

/// Non-fatal release self-check; only adds verdict lines to the boot output.
fn release_self_check() {
    let check = zns_tee_handoff::verify::self_check(
        live_measurement().ok(),
        zns_tee_handoff::verify::baked_tag(),
        &zns_tee_handoff::verify::GitHubRelease::default(),
    );
    println!("release_self_check={}", check.status);
    if !check.detail.is_empty() {
        println!("release_self_check_detail={}", check.detail);
    }
}
