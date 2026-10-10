# MIGRATION — TEE custody handoff over generations

SEV-SNP guests hold a seed phrase that must never exist outside TEE RAM.
Custody of that seed moves between *generations* of guest images — `v1.x` →
`v2.x` → `v3.x` … — while the host, the operator, and the relay only ever see
ciphertext. This document describes the design, the ceremony, and the proof.

## Model

**GitHub releases are the sole authority and the sole store (Model 1).**

- No guest has a disk. VMs are disposable; the *release store* is the custodian.
- A custodian image can be re-booted at any time, forever: it fetches the
  custody state from the store, unseals it with a key derived from the AMD SNP
  chip + its own measurement, and re-arms. The migration window never closes.
- All guest↔store traffic is TLS to `api.github.com` and
  `github.com` only, with SHA-256 digest verification of every asset.
  No in-guest Sigstore, no third-party root of trust.

## Tags are custody generations

| Tag | Meaning |
| --- | --- |
| `vX.Y.0` | Image of custody generation `X`. Minor-only, machine-enforced by the release workflow (`vX.Y.Z` with `Z≠0` is rejected: a patch tag would falsely claim measurement continuity). |
| `v1.x` | Generation 1: the genesis custodian. |
| `v2.x+` | Successor generations until they hold custody; a successor that takes custody becomes the custodian for the next generation. |
| `custody-vN` | The sealed custody state after `N-1` migrations. One asset: `state` (168 bytes, magic `LNST0001`, sealed to chip × measurement × policy). |

Every image change is a new measurement, therefore a new release, therefore
bumpable only as a new minor of its generation or a new generation major.

## The seam

```
        console (UART socket, full duplex)             GitHub releases
  ┌────────────┐   MIGRATION v2.0.0   ┌────────────┐   announcement.txt
  │ M0 (v1.x)  │◄─────────────────────│   relay    │───────┐         ┌──────────┐
  │ custodian  │                      │ (untrusted)│       └────────►│ v2.0.0   │
  │ holds seed │──── WRAP ───────────►│            │◄────────────────│ release  │
  └────────────┘   ECIES(p256)        └─────┬──────┘  snp-measurement └──────────┘
                                             │ wrap → M1 console
                                       ┌─────▼──────┐
                                       │ M1 (v2.x)  │  unwraps with ephemeral d,
                                       │ successor  │  reseals under its chipkey,
                                       └────────────┘  prints CUSTODY_STATE_BLOB
```

1. **Announce** — M1 boots, generates an ephemeral ECIES key `d`/`Q`, and
   prints `ANNOUNCE_BEGIN … pubkey=Q report=<VCEK-signed attestation with
   report_data = H(Q)> … ANNOUNCE_END`. The operator pins it as
   `announcement.txt` *inside the M1 release*.
2. **Trigger** — the relay types one line into M0's console:
   `MIGRATION v2.0.0`. The tag only *names* the successor; the console can
   never inject data.
3. **Verify + wrap** — M0 fetches the named release over TLS, checks the
   measurement asset, the policy, and that the announcement's attestation
   binds `Q` to the successor's own measurement (`report_data = H(Q)`,
   VCEK-signed). Only then does it ECIES-wrap the seed to `Q` and print the
   `WRAP` block.
4. **Take custody** — M1 unwraps with `d` (which dies with the VM), reseals
   the seed under its own chipkey/measurement/policy, and prints the
   `CUSTODY_STATE_BLOB`. The operator publishes it as `custody-v2`.

### Why the host cannot forge or steal

- Forging an announcement requires a VCEK-signed report binding an attacker
  key to the successor's measurement — which requires booting the real
  successor image; the host never learns `d` either way.
- The relay can censor, garble, or replay — all of which merely stall the
  ceremony (M0 ignores malformed triggers and remains standing custodian;
  M1 discards corrupted wraps and waits for a fresh one).
- The seed exists in plaintext only inside guest RAM of the current
  custodian generation.

## The console channel (hard-won lessons)

- **Never trust chardev logfiles.** QEMU's `qemu_chr_write_log` is documented
  best-effort: it silently drops bytes on transient write errors and can
  duplicate bytes across EAGAIN retries. We observed both. Logfiles are
  human-readable artifacts only — never a data channel.
- **The emulated UART is flow-controlled.** QEMU reads from the console
  socket only as fast as the guest drains its FIFO
  (`serial_can_receive`), so TCP backpressure paces a plain `sendall` at
  exactly the guest's drain rate. No manual chunking, no sleeps.
- **One persistent, full-duplex connection.** The relay connects once per
  phase, reads continuously (the socket stream is the only trustworthy copy
  of guest output), writes plain lines, and matches markers on completed
  lines only (a recv chunk can split a line mid-marker).

## Ceremony

Run as root on the isolated SNP host (`scripts/migration-ceremony.py`), one
phase at a time; `gh`/`scp` relay steps run from an authenticated machine
(they use a different API quota than the unauthenticated host):

```
verify    v1.0.0 v2.0.0    digest-check both image releases
genesis   v1.0.0           fresh seed → custody-v1        (relay: gh release create)
recover   v1.0.0           custody-v1 → armed custodian   (resurrection path)
announce  v1.0.0 v2.0.0    M1 announces                  (relay: gh release upload)
migration v1.0.0 v2.0.0    MIGRATION v2.0.0 → wrap → custody-v2
verify-m1 v1.0.0 v2.0.0    fresh M1 boot recovers custody-v2, fingerprint match
```

Markers (all printed to the console stream, never parsed from logfiles):
`m0_state_created=ok`, `m0_migration_armed=ok`,
`m0_migration_ignored=ok`, `m0_migration_complete=ok`,
`m1_announced=ok`, `m1_wrap_noise=ok`, `m1_wrap_error=…`,
`m1_custody_taken=ok`, `state_recovered=ok`, `release_self_check=accept`,
plus the `GENESIS_STATE_BLOB`, `ANNOUNCE`, `WRAP`, and `CUSTODY_STATE_BLOB`
delimited blocks.

Operational discipline: VMs are stopped only through their own QMP socket
after `query-name` verification; production guests are never touched;
unauthenticated GitHub API from the host is rate-limited to 60 req/h — run
each phase once.

## Proof (2026-10-10)

Lineage `v1.0.0 → v2.0.0`, seed (dummy)
`d1d9635bea9912d4354f03f0cf6bdeb397d7ee222719010bbdfcc352dcc3d943`:

1. Genesis under `v1.0.0`: seed born in TEE RAM, sealed, `custody-v1`
   published, self-check accepted (`tag v1.0.0 measurement matches this
   guest`), custodian armed.
2. `v2.0.0` announced; announcement pinned inside its release.
3. `MIGRATION v2.0.0` delivered over the console socket; M0 verified the
   announcement against the release and VCEK report; ECIES wrap captured
   from the socket stream; M1 unwrapped, re-sealed; `custody-v2` published.
4. Fresh `v2.0.0` boot: recovered `custody-v2` from the store,
   **fingerprint identical** — and armed itself as the custodian of the next
   generation, proving the chain extends: `MIGRATION v3.0.0` is all the next
   era needs.

Result: `MIGRATION VERIFIED: seed d1d9635b… recovered by v2.0.0`.
