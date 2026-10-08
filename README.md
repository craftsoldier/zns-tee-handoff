# zns-tee-handoff

Experimental SEV-SNP custody handoff using dummy secrets. This repository is
private under craftsoldier. No production seed, signing key, capsule, guest disk,
or private credential belongs here.

## Status

Planning and host inspection only. No handoff implementation, security audit,
guest launch, or hardware validation has been completed.

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
