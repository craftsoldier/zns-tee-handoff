# The Ceremony

The proven runbook. Every step below has been executed on real SEV-SNP
hardware with a dummy seed, end to end, more than once.

## Proven lineages

| Date | Lineage | Seed (dummy) | Notes |
| --- | --- | --- | --- |
| 2026-10-09 | `m0-v0.17.0 → m1-v0.5.0` | `d1d9635b…` | first full MIGRATION VERIFIED (pre-generation-tag scheme) |
| 2026-10-10 | `v1.0.0 → v2.0.0` | `bce7a273…` | generation tags, `MIGRATION` trigger verb, **M1 lineage check** (unwrap must match the custody fingerprint) |

## Phases

```
verify    TAG_M0 TAG_M1    digest-check both image releases
genesis   TAG_M0           fresh seed in TEE RAM → custody-v1     (once, ever)
recover   TAG_M0           custody-vN → unseal → armed listener   (resurrection, proven 3×)
announce  TAG_M0 TAG_M1    M1 boots, prints Q + report, waits
migration TAG_M0 TAG_M1    MIGRATION trigger → wrap → reseal → custody-v(N+1)
verify-m1 TAG_M0 TAG_M1    fresh M1 boot recovers custody-v(N+1), fingerprint match
```

## The artifacts (all public-safe by construction)

| Artifact | Contents | Character |
| --- | --- | --- |
| `announcement.txt` | `pubkey=Q` (ephemeral p256, `d` dies with the VM) + `report=` (1184-byte VCEK-signed SNP report: measurement, chip_id, `report_data = H(Q)`) | **authorization** — must reach M0 only via the trusted store |
| `WRAP` block | `ephemeral_pubkey=` + `blob=` (ECIES to Q; header = `MIGW0001 ‖ fingerprint ‖ H(Q) ‖ H(E)` as AAD) | **payload** — ciphertext; any courier is fine |
| `custody-vN/state` | `LNST0001 ‖ fingerprint(32) ‖ sealed_for measurement(48) ‖ AEAD ct` = 168 bytes | result; header fields are **plaintext and public** |

## The trigger

`MIGRATION v2.0.0\n` typed into the custodian's console. The tag only *names*
— strict `vX.Y.Z`, next generation only (`major == mine + 1`). The console can
never inject data; M0 fetches everything from the release itself. Fail-safe:
garbage lines ignored, standing custodian retained, trigger-before-publish is
a harmless 404 no-op.

## Draft → publish (the commit point)

Releases have two lives: **draft** (operator-only, editable, invisible to
anonymous guests) and **published** (public, and under immutable releases,
frozen forever). The announcement can't exist before the image release, and
can't be added after immutability — the draft is the escape:

```
CI: create v2.0.0 as DRAFT (image + measurement)
operator: boot M1 from the draft's files (host-side, auth'd gh)
M1 announces → attach announcement.txt to the draft
operator: PUBLISH           ← the swearing-in; trigger can only name published
operator: MIGRATION v2.0.0  ← on M0's console, wherever M0 lives
```

## The console channel (hard-won lessons)

- **Never trust chardev logfiles** — QEMU's `qemu_chr_write_log` is documented
  best-effort; observed dropping and duplicating bytes mid-line. Logs are for
  humans; data flows only over the socket stream.
- **The emulated UART is flow-controlled** — QEMU reads the socket only as
  fast as the guest drains its FIFO (`serial_can_receive`), so a plain
  `sendall` is paced by the guest itself. No manual chunking; it fights a
  working mechanism.
- **One persistent, full-duplex connection**; match markers on **completed
  lines only** (a recv chunk can split a line mid-marker); the stream merges
  guest prints with input echoes — origin is indistinguishable, so only
  content checks count.
- **Tolerant intake everywhere**: garbled blocks discarded, session keeps
  waiting (`m1_wrap_noise`, `m1_lineage_mismatch`); `d` dies with the process,
  so survival is the design goal.

## Cross-machine operation

The ceremony is VCEK-agnostic (reports verify against ARK) and shares no wire
between guests. The operator is the wire: capture the WRAP off machine A's
console, paste into machine B's. Everything carried is public-safe ciphertext.
The only irreducible same-machine path is *recovery* (the seal) — hence the
operational rule: **migrate before decommissioning**.
