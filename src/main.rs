use anyhow::{bail, Context, Result};
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
            println!("Usage:\n  zns-tee-handoff demo\n  zns-tee-handoff m0 create NEW_DIRECTORY\n  zns-tee-handoff m0 recover DIRECTORY\n\nDummy secrets only. m0 commands require a Linux SNP guest. No M1 handoff yet.");
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

#[allow(dead_code)]
fn read_record(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).context("inspect record")?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "record must be a regular file"
    );
    anyhow::ensure!(metadata.len() <= 16 * 1024, "record too large");
    std::fs::read(path).context("read record")
}
