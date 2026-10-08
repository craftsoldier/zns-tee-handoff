use anyhow::{bail, Result};

#[cfg(target_os = "linux")]
mod snp;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [arg] if arg == "demo" => demo(),
        [role, command, challenge] if role == "m0" && command == "boot" => {
            let bytes = hex::decode(challenge)?;
            let challenge: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("challenge must be 32 bytes"))?;
            boot(challenge)
        }
        [arg] if arg == "--help" || arg == "-h" => {
            println!(
                "Usage:\n  zns-tee-handoff demo\n  zns-tee-handoff m0 boot CHALLENGE_HEX\n\n\
                 CHALLENGE_HEX is 32 bytes (64 hex characters) supplied by the launcher\n\
                 for report freshness. The lineage state is fetched from — or, on a\n\
                 fresh lineage, printed for relay to — the baked lineage release.\n\
                 Requires a Linux SNP guest with network."
            );
            Ok(())
        }
        _ => bail!("invalid arguments; use --help"),
    }
}

/// Pure-crypto smoke test of the state envelope. No files, hardware, or network.
fn demo() -> Result<()> {
    let chip_key = zns_tee_handoff::random_secret()?;
    let seed = zns_tee_handoff::random_secret()?;
    let blob = zns_tee_handoff::state::seal(&chip_key, &seed, &[0; 48], 0)?;
    let opened = zns_tee_handoff::state::open(&chip_key, &blob)?;
    anyhow::ensure!(opened == seed.as_ref(), "state roundtrip mismatch");
    println!(
        "state_blob_sha256={}",
        hex::encode(zns_tee_handoff::hash(&blob))
    );
    println!(
        "dummy_seed_sha256={}",
        hex::encode(zns_tee_handoff::hash(&seed[..]))
    );
    println!("local_roundtrip=ok; no files, attestation, network, or persistence");
    Ok(())
}

fn boot(challenge: [u8; 32]) -> Result<()> {
    #[cfg(target_os = "linux")]
    return snp::boot(challenge);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = challenge;
        bail!("m0 boot requires a Linux SEV-SNP guest; use demo for a local test")
    }
}
