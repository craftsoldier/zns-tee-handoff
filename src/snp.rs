//! Stateless lineage boot: fetch or create the sealed seed, then self-check.
//! No disks: state lives in the lineage release; the seed only exists in RAM.
use anyhow::{ensure, Context, Result};
use hkdf::Hkdf;
use sev::{
    firmware::guest::{AttestationReport, DerivedKey, Firmware, GuestFieldSelect},
    parser::ByteParser,
};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;
use zns_tee_handoff::{hash, random_secret, state, verify};

const POLICY: u64 = 0x30000;

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

/// Fetch the lineage state from its release, or create it on a fresh lineage.
pub fn boot(challenge: [u8; 32]) -> Result<()> {
    let lineage = state::baked_lineage();
    let source = verify::GitHubRelease::default();
    let mut firmware =
        Firmware::open().context("open /dev/sev-guest; run inside a dedicated SNP test guest")?;
    let chip_key = chip_key(&mut firmware)?;
    match state::fetch_latest(lineage, &source)? {
        None => genesis_state(&mut firmware, &chip_key)?,
        Some(blob) => recover_state(&mut firmware, &chip_key, &blob, challenge)?,
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
    println!("lineage_state_sha256={}", hex::encode(hash(&blob)));
    println!("dummy_seed_sha256={}", hex::encode(hash(&seed[..])));
    println!("genesis_report_hex={}", hex::encode(&report));
    println!(
        "m0_state_created=ok; sealed to this chip, measurement, and policy; \
         relay the blob to the lineage release as state-v1"
    );
    Ok(())
}

fn recover_state(
    firmware: &mut Firmware,
    chip_key: &[u8; 32],
    blob: &[u8],
    challenge: [u8; 32],
) -> Result<()> {
    let seed = state::open(chip_key, blob)?;
    let fingerprint = hash(&seed);
    let mut binding = Sha512::new();
    binding.update(b"zns-tee-handoff/stateless-recovery/v1");
    binding.update(challenge);
    binding.update(Sha256::digest(blob));
    binding.update(fingerprint);
    let report = firmware.get_report(Some(1), Some(binding.finalize().into()), Some(0))?;
    println!("dummy_seed_sha256={}", hex::encode(fingerprint));
    println!("lineage_state_sha256={}", hex::encode(hash(blob)));
    println!("recovery_challenge={}", hex::encode(challenge));
    println!("recovery_report_hex={}", hex::encode(&report));
    println!("m0_state_recovered=ok; state fetched from the lineage release");
    Ok(())
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
