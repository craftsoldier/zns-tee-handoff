# zns-tee-handoff

Experimental SEV-SNP custody handoff using dummy secrets. This repository is
public under craftsoldier. No production seed, signing key, capsule, guest disk,
or private credential belongs here.

## Status

Initial M0 dummy capsule generation and local SNP chip-sealing code exist.
No M1 handoff, release approval verification, certificate verification, guest
launch, or hardware validation has been completed. This is not audited software.

## First M0 program

`cargo run --locked -- demo` generates dummy seed and SK, encrypts and decrypts
the capsule in memory, and prints only public hashes. It writes no files and
provides no TEE or persistence assurance.

Inside a dedicated Linux SNP test guest:

```text
zns-tee-handoff m0 create /state/new-dummy-genesis
zns-tee-handoff m0 recover /state/new-dummy-genesis
```

Creation requires a new destination directory and policy `0x30000`. It writes
the capsule, chip-wrapped SK, a raw genesis report, and public JSON metadata.
It never writes the raw seed or SK. The wrapping key is an HKDF-separated key
from the SNP derived-key interface, bound to actual guest policy and measurement.
The authenticated chip-layer header binds chip ID, measurement, policy, and
capsule hash. Recovery checks those bindings and prints the recovered seed's
public SHA-256 fingerprint. This is local recovery, not the M1 handoff.

If file creation fails midway, the partial directory is retained and creation
refuses to overwrite it. A report collected by this initial program is not an
approved measurement record or peer authentication: certificate verification
and signed release approval remain to be implemented. These commands must not
run on existing production guests or access production state.

The code has no plaintext key export or development wrapping-key fallback.
Persistent key creation requires `/dev/sev-guest`; the bare-metal host's
`/dev/sev` interface is not a substitute. Unit tests check capsule recovery,
wrong-key rejection, tampering, truncation, and wrapping context authentication.
Passing those tests does not establish hardware recovery or protocol security.

Changes are committed and pushed before any server transfer. Linux CI compiles
the SNP code and tests the dummy cryptography without launching a VM or accessing
hardware keys. Future build and release artifacts must refer to an exact pushed
commit SHA; they are not generated from an uncommitted working tree. Runtime
verification of release approval is still not implemented.

## Automated guest releases

`.github/workflows/release.yml` runs manually for validation or on a new `m0-v*`
tag for publication. It checks out the triggering SHA, runs the tests, and uses
`image/build.py` to build a custom Ubuntu-package-based initramfs containing M0.
No Nix, Buildroot, VM launch, production code, or server access is involved.

The kernel, SNP driver modules, OVMF, and guest packages are content-hash pinned
in `image/pins.json`. Rust and Cargo.lock are pinned; measurement dependencies
are hash-locked for Python 3.12 in `image/measurement-requirements.txt`. Ubuntu
runner native build utilities are not a fully hermetic toolchain. Two clean
runner jobs must produce byte-identical outputs before the publish job runs.
This verifies repeatability for that run, not universal reproducibility.

The launch profile targets QEMU on the inspected EPYC 8024P (CPU 25/160/2), two
vCPUs, 1 GiB RAM, policy `0x30000`, features `0x1`, and kernel hashes enabled.
Policy is a separate attestation check, not part of the launch digest. CPU and
other profile changes require a new measurement. Boot configuration must enforce
the kernel/initramfs hashes; no successful hardware launch is claimed yet.

The guest init program runs dummy creation and same-boot recovery, emits public
metadata and a raw report in base64, then waits without opening a shell. Guest
state lives in tmpfs and is lost on shutdown. No disks or networking are needed;
this first image does not test durable recovery across a reboot.

Release assets:

- `m0-initrd.img`, `vmlinuz`, `OVMF.amdsev.fd`, and `zns-tee-handoff`.
- `launch-profile.json`, `snp-measurement.txt`, and `release-manifest.json`.
- `SHA256SUMS` covering all other assets.

The manifest records the actual source commit and expected offline measurement.
GitHub provenance attestations bind the asset digests to the publishing workflow;
they do not replace live AMD attestation or define your runtime approval policy.
Consumers must constrain the repository, signer workflow, commit/tag policy, and
artifact digest when verifying provenance. Never trust an unsigned manifest just
because its measurement matches a report.

Push the workflow commit first, validate it with a manual run, then push a new
tag on that commit. Existing release tags must not be moved. The workflow uses
the triggering tag, never a mutable lookup of the latest release, and creates a
prerelease only after both builds match. To verify downloaded artifact provenance:

```text
gh attestation verify release-manifest.json --repo craftsoldier/zns-tee-handoff --signer-workflow craftsoldier/zns-tee-handoff/.github/workflows/release.yml
sha256sum --check SHA256SUMS
```

After verifying the authenticated manifest, consumers must also check its source
commit, launch profile, and artifact hashes against their approval policy.

## Intended experiment

1. Build two reproducible guest images containing all code handling secrets.
2. Compute expected SNP measurements offline using the exact launch inputs.
3. Publish authenticated release manifests binding image digests, source commits,
   measurements, launch profiles, and required security policy.
4. Generate temporary key pairs inside the guests. Verify fresh mutual AMD
   attestation binding those public keys to the approved guest contexts.
5. Transfer one dummy capsule encryption key using a standard cryptographic
   implementation. Specify sender authentication, transcript bindings, freshness,
   release trust, and custody identity before implementing the exchange.
6. Authenticate and decrypt the original dummy capsule at the recipient.
7. Seal the capsule key to the recipient's hardware and measured context, then
   demonstrate recovery after restarting the test guest.
8. Reject substituted keys, mismatched measurements, altered ciphertext, wrong
   capsule identity, and replayed handoff messages.

The persistent capsule key and the temporary DH-derived transfer key are separate.
Release approval and intended-instance approval must have explicitly defined trust
anchors. Successful tests are not a complete cryptographic security audit.

## Server isolation

Use `/home/ubuntu/dh_tests` for experiment artifacts. Existing guests and their
disks are outside the experiment. Do not modify existing launch scripts, images,
networks, or services. Do not reboot the host or update firmware for this test.
Future launches require dedicated disks, ports, logs, and bounded resources after
checking the existing allocations. Restart only an experiment guest.

Read-only inspection on 2026-10-09 found an AMD EPYC 8024P, kernel
`7.0.0-15-generic`, `/dev/kvm` and `/dev/sev`, and both KVM AMD `sev` and
`sev_snp` parameters set to `Y`. One QEMU process was running. Approximately
52 GiB memory was available. This establishes reported host capabilities, not
successful guest attestation or a security assessment of the platform firmware.

## Planned layout

- `guest/`: sender/receiver program and trust verification.
- `build/`: pinned guest image builds and launch profiles.
- `scripts/`: offline measurement, isolated launch, and test orchestration.
- `docs/`: protocol specification, threat model, and audit findings.
- `releases/`: public metadata only; no secret signing material.
