//! Stateless seeded boot plus the M0→M1 handoff seam.
//!
//! Roles are selected by the baked release tag's major version (the custody
//! generation):
//! - generation 1 `v1.x` (custodian): fetch-or-create the custody state, then
//!   listen on the console for `MIGRATION <next-generation tag>` and wrap the
//!   seed for the successor announced inside that release.
//! - generation >= 2 `v2.x+` (successor): announce an ephemeral ECIES key on
//!   the console and wait for the wrap; re-seal the seed under this image's
//!   own measurement. A successor that holds custody becomes the custodian
//!   for the next generation.
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
use std::io::BufRead;
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

/// The baked release tag's major version is this image's custody generation;
/// generation >= 2 images are successors until they hold custody.
fn generation() -> Option<u32> {
    verify::baked_tag().and_then(verify::parse_generation)
}

fn is_successor() -> bool {
    generation().is_some_and(|generation| generation >= 2)
}

/// Fetch or create the custody state, then — as custodian — listen for a
/// migration trigger on the console. Non-fatal: a timeout simply leaves this
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
                // No lineage exists yet, so there is no published
                // fingerprint to enforce against.
                successor_boot(&mut firmware, &chip_key, None)?;
            } else {
                let seed = genesis_state(&mut firmware, &chip_key)?;
                release_self_check();
                println!("M0_TEST_COMPLETE: genesis done; migration armed");
                migration_listen(&seed, &source)?;
            }
        }
        Some(blob) => {
            let sealed_for = state::blob_measurement(&blob)?;
            if sealed_for == measurement {
                // This generation holds custody: recover, then offer migration.
                let seed = state::open(&chip_key, &blob)?;
                recover_state(&mut firmware, &blob, &seed, challenge)?;
                println!("M0_TEST_COMPLETE: custody recovered; migration armed");
                // The custody holder is the custodian, whatever its
                // generation: a successor that has taken custody arms for
                // the next migration.
                migration_listen(&seed, &source)?;
            } else if is_successor() {
                // The current state is sealed for a different generation:
                // announce and take custody. The wrap must carry the seed
                // the fetched lineage blob already fingerprints.
                let lineage = state::fingerprint_of(&blob)?;
                successor_boot(&mut firmware, &chip_key, Some(&lineage))?;
            } else {
                println!(
                    "m0_stand_down=ok; custody is held by a newer generation; \
                     this image remains bootable for recovery and migration"
                );
            }
        }
    }
    release_self_check();
    Ok(())
}

fn genesis_state(firmware: &mut Firmware, chip_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
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
    Ok(seed)
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

/// Custodian side of the seam: ARMED after genesis or recovery. Blocks on the
/// console waiting for `MIGRATION <next-generation tag>`; the tag only names the successor —
/// the announcement is fetched from that release (GitHub, digest-verified).
/// Garbage on the console is ignored: the fail-safe is "no handoff, remain
/// custodian", and the trigger can be re-sent at any time.
fn migration_listen(seed: &[u8; 32], source: &verify::GitHubRelease) -> Result<()> {
    println!("m0_migration_armed=ok; console trigger: MIGRATION <next-generation tag>");
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { return Ok(()) };
        let Some(tag) = line.strip_prefix("MIGRATION ") else {
            continue;
        };
        let Some(next) = verify::parse_generation(tag) else {
            println!("m0_migration_ignored=ok; tag must be vX.Y.Z");
            continue;
        };
        if generation().is_none_or(|generation| next != generation + 1) {
            println!("m0_migration_ignored=ok; tag must be the next generation");
            continue;
        }
        match self_migration(seed, source, tag) {
            Ok(()) => {
                println!(
                    "m0_migration_complete=ok; seed wrapped for the successor announced in {tag}"
                );
                return Ok(());
            }
            Err(error) => {
                println!("m0_migration_error={error}; remaining standing custodian");
            }
        }
    }
    Ok(())
}

/// Verify the successor announcement published inside `tag`'s release and
/// print the ECIES-wrapped seed.
fn self_migration(seed: &[u8; 32], source: &verify::GitHubRelease, tag: &str) -> Result<()> {
    let release = verify::fetch_release(source, tag)?
        .ok_or_else(|| anyhow::anyhow!("successor release not found"))?;
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("successor release has no assets"))?;
    let find = |name: &str| {
        assets
            .iter()
            .find(|a| a["name"].as_str() == Some(name))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("successor release missing {name}"))
    };
    let measurement_asset = find("snp-measurement.txt")?;
    let announcement_asset = find("announcement.txt")?;
    let measurement_bytes = verify::download_asset_checked(source, &measurement_asset)?;
    let announcement_bytes = verify::download_asset_checked(source, &announcement_asset)?;

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
    Ok(())
}

fn successor_boot(
    firmware: &mut Firmware,
    chip_key: &[u8; 32],
    lineage_fingerprint: Option<&[u8; 32]>,
) -> Result<()> {
    let secret = SecretKey::random(&mut rand::rngs::OsRng);
    let pubkey = secret.public_key().to_encoded_point(false);
    let binding = state::announcement_report_data(pubkey.as_bytes());
    let report = firmware.get_report(Some(1), Some(binding), Some(0))?;
    println!("ANNOUNCE_BEGIN");
    println!("pubkey={}", hex::encode(pubkey.as_bytes()));
    println!("report={}", hex::encode(&report));
    println!("ANNOUNCE_END");
    println!("m1_announced=ok; waiting for the migration wrap on the console");

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    // The emulated UART can drop bytes from bursts, so a wrap block may arrive
    // garbled. That must never kill this session: `d` dies with the process,
    // and losing it forces a full re-announce. Bad blocks are rejected and a
    // fresh WRAP block awaited instead.
    let seed = loop {
        let (ephemeral_pubkey, wrap_blob) = read_wrap_block(&mut reader)?;
        let seed = match state::unwrap_seed(&secret, &ephemeral_pubkey, &wrap_blob) {
            Ok(seed) => seed,
            Err(error) => {
                println!("m1_wrap_error={error}; waiting for a fresh wrap");
                continue;
            }
        };
        // Lineage continuity: Q is public, so anyone can wrap ANY seed to
        // it. A wrap that decrypts but carries a foreign seed must never be
        // re-sealed — only the seed whose fingerprint the custody lineage
        // already publishes (the plaintext header of the fetched blob).
        match lineage_fingerprint {
            Some(expected) if hash(&seed) != *expected => {
                println!(
                    "m1_lineage_mismatch=ok; wrap carries a foreign seed; \
                     waiting for the lineage wrap"
                );
                continue;
            }
            _ => break seed,
        }
    };
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
            if inside {
                println!("m1_wrap_noise=ok; restart at a fresh WRAP_BEGIN");
            }
            ephemeral_pubkey = None;
            blob = None;
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if line == "WRAP_END" {
            match (ephemeral_pubkey.take(), blob.take()) {
                (Some(pubkey), Some(wrap)) => return Ok((pubkey, wrap)),
                _ => println!("m1_wrap_noise=ok; incomplete block, continuing"),
            }
            inside = false;
            continue;
        }
        let field = |line: &str, name: &str| -> Option<Vec<u8>> {
            line.strip_prefix(name)
                .and_then(|value| hex::decode(value).ok())
                .or_else(|| {
                    if line.starts_with(name) {
                        println!("m1_wrap_noise=ok; discarding bad {name}, continuing");
                    }
                    None
                })
        };
        if let Some(value) = field(&line, "ephemeral_pubkey=") {
            ephemeral_pubkey = Some(value);
        }
        if let Some(value) = field(&line, "blob=") {
            blob = Some(value);
        }
    }
    anyhow::bail!("console closed before a complete wrap arrived")
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
