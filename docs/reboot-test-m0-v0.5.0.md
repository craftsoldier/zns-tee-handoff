# M0 reboot test: m0-v0.5.0

Test completed on the isolated SNP host on 2026-10-09.

- Source commit: `685e427fdfb5dc26fa5db634fd0706b59b8ed493`.
- Release workflow run: https://github.com/craftsoldier/zns-tee-handoff/actions/runs/37842470523
- Two independent builds produced identical release files.
- GitHub build provenance verified for the release manifest under the expected
  repository and `.github/workflows/release.yml` signer workflow.
- Manifest SHA-256: `cd244d564a7d3d729f6e1a8c7ade95c5d7900638fc1ba48500a46b5621a0169a`.
- Guest: 4096 MiB RAM, two vCPUs, no network, dedicated 256 MiB ext4 disk.
- Same image, command line, policy `0x30000`, chip and launch inputs on both boots.

## Results

1. First boot generated dummy seed and SK, wrote encrypted state, recovered it,
   synced and unmounted the disk. Its QEMU process was then terminated via its
   name-checked QMP socket.
2. A separate QEMU process booted with the same disk and recovered the same seed.
   It did not execute secret creation.
3. Fresh recovery reports from both boots matched their different host-generated
   challenges, all 48 bytes of the released measurement, and the expected policy.
   The pinned AMD ARK matched the certificate root; the ASK/VCEK chain, report
   signatures and TCB checks passed using snpguest.
4. A third boot with a modified capsule failed recovery without regenerating
   secrets. The original capsule was restored afterward with the test VM stopped.

Seed SHA-256: `fb4d68cfe67f6686fe8f95b6b290d197d608fb32ed1ae1ba3a6980e909c2fe35`.

Capsule SHA-256: `7dfa6f05a57ae2e097dddbcb97f078c083b44ba78b7d566645e629caf9fa0375`.

Chip-layer SHA-256: `c60837d8becadbebb14875038186382d8dacc7f9f45cd8df547e23d639d2ffd2`.

SNP measurement:
`c0ac09eb9957dbee62a4479d376ee5a2e889afd446dc857bdbfc7d1e7e547574e57f55c9ec79b98edad0fc82c1d8ea18`.

Evidence is retained on the host under
`/home/ubuntu/dh_tests/m0-v0.5.0/runtime`: boot logs, fresh report binaries,
public challenges and `verification.json`. Existing production assets were not
modified. Only the named older v0.4.0 experiment and the new test VMs were stopped.

## Scope

This demonstrates orderly persistent recovery after destroying VM memory. It does
not demonstrate power-loss durability, firmware or chip migration, anti-rollback,
release approval inside the guest, or M1/DH handoff. Report verification is done
by the external test. The raw seed and plaintext SK are never exported.
