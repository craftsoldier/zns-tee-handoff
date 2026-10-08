//! Local chip sealing only. Reports here are evidence, not verified approvals.
use anyhow::{ensure, Context, Result};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sev::{
    firmware::guest::{AttestationReport, DerivedKey, Firmware, GuestFieldSelect},
    parser::ByteParser,
};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};
use zeroize::Zeroizing;
use zns_tee_handoff::{decrypt, encrypt, hash, open_capsule, Genesis};

const HEADER_LEN: usize = 160;
const LAYER_LEN: usize = HEADER_LEN + 24 + 32 + 16;
const POLICY: u64 = 0x30000;

fn context(firmware: &mut Firmware, capsule_hash: &[u8; 32]) -> Result<Vec<u8>> {
    let raw = firmware.get_report(Some(1), Some([0; 64]), Some(0))?;
    let report = AttestationReport::from_bytes(&raw)?;
    ensure!(report.policy.0 == POLICY, "guest policy must be 0x30000");
    ensure!(
        report.chip_id != [0; 64],
        "chip identity is masked or unavailable"
    );
    ensure!(report.measurement != [0; 48], "missing launch measurement");
    let mut header = b"DHWRP001".to_vec();
    header.extend_from_slice(&report.chip_id);
    header.extend_from_slice(&report.measurement);
    header.extend_from_slice(&POLICY.to_le_bytes());
    header.extend_from_slice(capsule_hash);
    Ok(header)
}

fn wrapping_key(firmware: &mut Firmware) -> Result<Zeroizing<[u8; 32]>> {
    let mut fields = GuestFieldSelect::default();
    fields.set_guest_policy(true);
    fields.set_measurement(true);
    let request = DerivedKey::new(false, fields, 0, 0, 0, None);
    let raw = Zeroizing::new(firmware.get_derived_key(Some(1), request)?);
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(None, raw.as_ref())
        .expand(b"zns-tee-handoff/dummy-chip-wrap/v1", key.as_mut())
        .map_err(|_| anyhow::anyhow!("wrapping key derivation failed"))?;
    Ok(key)
}

fn write_new(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))
        .context("create output file")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct PublicRecord {
    format: String,
    dummy_seed_sha256: String,
    capsule_sha256: String,
    chip_layer_sha256: String,
    attestation_report_sha256: String,
    warning: String,
}

pub fn create(directory: &Path) -> Result<()> {
    let mut firmware =
        Firmware::open().context("open /dev/sev-guest; run inside a dedicated SNP test guest")?;
    let genesis = Genesis::generate()?;
    let capsule_hash = hash(&genesis.capsule);
    let header = context(&mut firmware, &capsule_hash)?;
    let key = wrapping_key(&mut firmware)?;
    let layer = encrypt(&key, &header, genesis.sk.as_ref())?;
    // Check the persisted representation before writing it.
    let recovered_sk = decrypt(&key, &layer, HEADER_LEN)?;
    ensure!(
        recovered_sk.as_slice() == genesis.sk.as_ref(),
        "chip layer roundtrip failed"
    );
    let mut binding = Sha512::new();
    binding.update(b"zns-tee-handoff/dummy-genesis/v1");
    binding.update(capsule_hash);
    binding.update(hash(&layer));
    let report = firmware.get_report(Some(1), Some(binding.finalize().into()), Some(0))?;
    let record = PublicRecord {
        format: "dummy-genesis-v1".into(),
        dummy_seed_sha256: hex::encode(genesis.fingerprint),
        capsule_sha256: hex::encode(capsule_hash),
        chip_layer_sha256: hex::encode(hash(&layer)),
        attestation_report_sha256: hex::encode(hash(&report)),
        warning: "Test evidence only. No certificate verification, release approval, or M1 handoff implemented.".into(),
    };
    // Refuse an existing destination, including an existing symlink.
    fs::DirBuilder::new()
        .mode(0o700)
        .create(directory)
        .context("destination must be a new directory")?;
    write_new(directory, "seed.capsule", &genesis.capsule)?;
    write_new(directory, "sk.chip-layer", &layer)?;
    write_new(directory, "genesis-report.bin", &report)?;
    write_new(
        directory,
        "genesis.json",
        &serde_json::to_vec_pretty(&record)?,
    )?;
    fs::File::open(directory)?.sync_all()?;
    if let Some(parent) = directory.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::File::open(parent)?.sync_all()?;
    }
    println!("dummy_seed_sha256={}", record.dummy_seed_sha256);
    println!("capsule_sha256={}", record.capsule_sha256);
    // The public report contains no seed or SK. Emit it without BusyBox applets.
    println!("attestation_report_hex={}", hex::encode(&report));
    println!("m0_created=ok; SK stored only as chip-wrapped ciphertext; no M1 handoff yet");
    release_self_check();
    Ok(())
}

pub fn recover(directory: &Path) -> Result<()> {
    recover_challenged(directory, [0; 32])
}

pub fn recover_challenged(directory: &Path, challenge: [u8; 32]) -> Result<()> {
    ensure!(
        fs::symlink_metadata(directory)?.is_dir(),
        "state path must be a directory"
    );
    let capsule = crate::read_record(&directory.join("seed.capsule"))?;
    let layer = crate::read_record(&directory.join("sk.chip-layer"))?;
    let record: PublicRecord =
        serde_json::from_slice(&crate::read_record(&directory.join("genesis.json"))?)?;
    ensure!(
        record.format == "dummy-genesis-v1",
        "incomplete or invalid genesis record"
    );
    ensure!(
        record.capsule_sha256 == hex::encode(hash(&capsule)),
        "capsule record mismatch"
    );
    ensure!(
        record.chip_layer_sha256 == hex::encode(hash(&layer)),
        "chip layer record mismatch"
    );
    let original_report = crate::read_record(&directory.join("genesis-report.bin"))?;
    ensure!(
        record.attestation_report_sha256 == hex::encode(hash(&original_report)),
        "genesis report mismatch"
    );
    ensure!(layer.len() == LAYER_LEN, "invalid chip layer length");
    let mut firmware = Firmware::open().context("open /dev/sev-guest")?;
    let expected = context(&mut firmware, &hash(&capsule))?;
    ensure!(
        layer[..HEADER_LEN] == expected,
        "chip layer belongs to a different chip, measurement, policy, or capsule"
    );
    let key = wrapping_key(&mut firmware)?;
    let plaintext = decrypt(&key, &layer, HEADER_LEN)?;
    ensure!(plaintext.len() == 32, "invalid wrapped key length");
    let mut sk = Zeroizing::new([0; 32]);
    sk.copy_from_slice(&plaintext);
    let seed = open_capsule(&sk, &capsule)?;
    let fingerprint = hash(seed.as_ref());
    ensure!(
        record.dummy_seed_sha256 == hex::encode(fingerprint),
        "seed record mismatch"
    );
    let mut binding = Sha512::new();
    binding.update(b"zns-tee-handoff/dummy-recovery/v1");
    binding.update(challenge);
    binding.update(hash(&capsule));
    binding.update(hash(&layer));
    binding.update(fingerprint);
    let report = firmware.get_report(Some(1), Some(binding.finalize().into()), Some(0))?;
    println!("dummy_seed_sha256={}", hex::encode(fingerprint));
    println!("capsule_sha256={}", hex::encode(hash(&capsule)));
    println!("chip_layer_sha256={}", hex::encode(hash(&layer)));
    println!("recovery_challenge={}", hex::encode(challenge));
    println!("recovery_report_hex={}", hex::encode(report));
    println!("m0_local_recovery=ok; no release or certificate verification performed");
    release_self_check();
    Ok(())
}

/// Live launch measurement from a fresh SNP report.
pub fn live_measurement() -> Result<[u8; 48]> {
    let mut firmware = Firmware::open().context("open /dev/sev-guest")?;
    let raw = firmware.get_report(Some(1), Some([0; 64]), Some(0))?;
    let report = AttestationReport::from_bytes(&raw)?;
    ensure!(report.measurement != [0; 48], "missing launch measurement");
    Ok(report.measurement)
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
