use anyhow::{bail, Context, Result};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use zns_tee_handoff::{hash, open_capsule, Genesis};

#[cfg(target_os = "linux")]
mod snp;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [command, device] if command == "check-test-disk" => check_test_disk(Path::new(device)),
        [role, command, directory, challenge] if role == "m0" && command == "recover" => {
            let bytes = hex::decode(challenge.to_string_lossy().as_ref())?;
            let challenge: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("challenge must be 32 bytes"))?;
            recover_challenged(Path::new(directory), challenge)
        }
        [command] if command == "demo" => {
            let genesis = Genesis::generate()?;
            let recovered = open_capsule(&genesis.sk, &genesis.capsule)?;
            println!(
                "dummy_seed_sha256={}",
                hex::encode(hash(recovered.as_ref()))
            );
            println!("capsule_sha256={}", hex::encode(hash(&genesis.capsule)));
            println!("local_roundtrip=ok; no files, attestation, persistence, or handoff");
            Ok(())
        }
        [role, command, directory] if role == "m0" && command == "create" => {
            create(Path::new(directory))
        }
        [role, command, directory] if role == "m0" && command == "recover" => {
            recover(Path::new(directory))
        }
        [command] if command == "--help" || command == "-h" => {
            println!("Usage:\n  zns-tee-handoff demo\n  zns-tee-handoff m0 create NEW_DIRECTORY\n  zns-tee-handoff m0 recover DIRECTORY [CHALLENGE_HEX]\n  zns-tee-handoff check-test-disk DEVICE\n\nCHALLENGE_HEX is 32 bytes as 64 hex characters; omitted means no freshness challenge.\nDummy secrets only. m0 commands require a Linux SNP guest. No M1 handoff yet.");
            Ok(())
        }
        _ => bail!("invalid arguments; use --help"),
    }
}

#[cfg(target_os = "linux")]
fn create(directory: &Path) -> Result<()> {
    snp::create(directory)
}
#[cfg(target_os = "linux")]
fn recover(directory: &Path) -> Result<()> {
    snp::recover(directory)
}

#[cfg(not(target_os = "linux"))]
fn create(_directory: &Path) -> Result<()> {
    bail!("m0 create requires a Linux SEV-SNP guest; use demo for a local test")
}
#[cfg(not(target_os = "linux"))]
fn recover(_directory: &Path) -> Result<()> {
    bail!("m0 recover requires a Linux SEV-SNP guest")
}

#[cfg(target_os = "linux")]
fn read_record(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).context("inspect record")?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "record must be a regular file"
    );
    anyhow::ensure!(metadata.len() <= 16 * 1024, "record too large");
    std::fs::read(path).context("read record")
}

#[cfg(target_os = "linux")]
fn recover_challenged(directory: &Path, challenge: [u8; 32]) -> Result<()> {
    snp::recover_challenged(directory, challenge)
}
#[cfg(not(target_os = "linux"))]
fn recover_challenged(_directory: &Path, _challenge: [u8; 32]) -> Result<()> {
    bail!("requires Linux SNP guest")
}

/// Check the dedicated test volume before PID 1 mounts it.
fn check_test_disk(device: &Path) -> Result<()> {
    const SUPERBLOCK_OFFSET: u64 = 1024;
    const MAGIC_OFFSET: usize = 56;
    const UUID_OFFSET: usize = 104;
    const TEST_UUID: &str = "df050000000040008000000000000005";

    let mut file = std::fs::File::open(device).context("open test volume")?;
    file.seek(SeekFrom::Start(SUPERBLOCK_OFFSET))?;
    let mut superblock = [0; 120];
    file.read_exact(&mut superblock)?;
    anyhow::ensure!(
        superblock[MAGIC_OFFSET..MAGIC_OFFSET + 2] == [0x53, 0xef],
        "test disk is not ext4"
    );
    anyhow::ensure!(
        hex::encode(&superblock[UUID_OFFSET..UUID_OFFSET + 16]) == TEST_UUID,
        "unexpected test disk UUID"
    );
    Ok(())
}
