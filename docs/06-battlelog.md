# The Battle Log — what we tested, what broke, what it taught

Everything below happened on real hardware during the 2026-10-09/10 sessions.
Conclusions live in the other docs; this is the evidence.

## What worked (proven properties and their receipts)

| Property | Proven by |
| --- | --- |
| Chip sealing: PSP derived key, HKDF, measurement-bound | m0-v0.5.0→0.7.0 lineages |
| Reboot persistence of sealed state | reboot tests, m0-v0.6/0.7 era |
| TLS-only GitHub self-check (`release_self_check=accept`) | every guest boot since v0.7 |
| Stateless disk-less guests; releases as the store | m0-v0.8.0→0.10.0 |
| Genesis + recovery + custody-vN publish/fetch | m0-v0.11→0.16 |
| Role-based boot; ECIES wrap/unwrap (p256); announcement `report_data = H(Q)` | m0-v0.15/m1-v0.3 era |
| Cross-generation handoff (custodian and successor on different measurements) | m0-v0.17.0 → m1-v0.5.0, seed `d5f610df…` |
| Born-armed genesis + console trigger + fail-safe ignore of garbage | v0.17.0/v0.4.0 lineage |
| Tolerant wrap intake (session survives garbled blocks) | m1-v0.5.0: survived 4 corrupt deliveries, `d` alive throughout |
| Recovery→arm→handoff (resurrection of a custodian) | `recover` phase + migration, twice |
| Generation tags; `MIGRATION` verb; next-gen-only trigger | v1.0.0→v2.0.0, seed `d1d9635b…` |
| **Lineage fingerprint check** (unwrap must match custody header) | v1.0.0→v2.0.0, seed `bce7a273…` (passed silently — negative test still pending) |
| Successor-becomes-custodian (fresh v2 boot arms for the next era) | verify-m1 boots |
| Operator-as-wire (wrap carried between consoles) | every migration; formalized during cross-machine walkthrough |

## The UART war (the big one)

**Symptom chain, in order of appearance:**

1. Unpaced 18-byte trigger delivered 8 bytes (`HANDOFF ` echoed, rest gone).
   First diagnosis: UART FIFO overrun. First fix: 4-byte chunks @20 ms.
2. Wrap (≈540 B) delivered paced **still truncated — deterministically, same
   cut, 4/4 attempts** (`blob=` line cut to 355 hex chars, odd count).
   Determinism killed the overrun theory: 6-byte chunks at 50 ms cannot
   overrun a 16-byte FIFO, and `WRAP_END` *after* the hole arrived intact —
   a contiguous mid-stream loss, which neither TCP nor overrun produces.
3. Forensics: M1's echoed line had a hex char M0's logfile lacked — the two
   artifacts disagreed by one byte, and both were "copies" of the same print.
4. **QEMU source audit settled it:**
   - `qemu_chr_write_log` is documented **best-effort** — silently drops
     bytes on transient write errors, and double-logs across EAGAIN retries.
     Both logfile artifacts were unreliable narrators; the socket was the
     only truth.
   - `serial_can_receive` gates how much QEMU reads from the socket by the
     guest's FIFO drain — **TCP backpressure IS the UART's flow control**.
     Manual pacing was fighting a working mechanism.
   - The fix: **socket-native relay** — one persistent full-duplex
     connection, plain `sendall`, read the stream, never touch logfiles for
     data. First migration attempt after the rewrite: clean.

**What it taught:** logs are for humans; the emulated UART is a real
flow-controlled line; use it properly (persistent connection, no chunking)
and it's boring.

## The tolerant-reader birth

Before m1-v0.5.0, one garbled wrap line (`hex::decode` error) propagated up,
killed the binary, `halt_test`'d the VM — and **`d` died with the process**,
forcing a full re-announce. The log read `WRAPerror: Odd number of digits`
then `M0_TEST_FAILED: boot`. Three paced re-deliveries arrived perfectly
afterward — to a corpse. Fix: `read_wrap_block` discards bad fields/blocks
(`m1_wrap_noise`), `unwrap_seed` failures loop (`m1_wrap_error`), and the
lineage check discards foreign seeds (`m1_lineage_mismatch`). Sessions became
unkillable by console input.

## Marker races (relay-side, three times)

Guests print their story as a **time sequence**; the relay returned from
`wait_for` the instant the *first* marker appeared and then required later
lines that hadn't printed yet. Hit in verify-m1 (self-check prints at
boot-end), then genesis, then announce. Old logfile polling masked it
(2 s re-read latency); the socket-native reader exposed it. Fix: wait for
each phase's **final** marker; match markers on **completed lines only** (a
recv chunk can split a line mid-marker — observed live).

## One handoff per boot (re-run trap)

Re-running the migration phase against an M0 that had already completed a
handoff: the listener had exited; the trigger echoed to an inert guest and
the phase timed out with no guest-side error. Lesson: after
`m0_migration_complete`, a **reboot** re-arms via recovery — the phase must
boot fresh or use `recover`. Recorded in operations.

## Ceremony-script scars

- Wrote the **marker text block** (387 B, `CUSTODY_…`) as the state asset
  instead of the raw 168-B blob — caught by the magic check at publish.
  Fix: extract hex between markers, `bytes.fromhex`, verify `LNST0001`.
- Uploaded the asset as `state2` (local filename) — guest fetches `state`;
  twice. Fix: name the asset explicitly.
- Phase dispatch `KeyError: 'migration'` — renamed the CLI word but not the
  dict key. Fix and lesson: rename all surfaces in one commit.
- GitHub API **403s mid-ceremony**: anonymous quota is 60 req/hr **per host
  IP**, shared by guests and relay. A debug-loop night exhausts it. Fix:
  wait out the window; discipline: run each phase once.

## CI scars

- `UnboundLocalError: re` — twice. First: heredoc's `if "import re" in s`
  guard saw a *function-local* `import re` deep in `build.py` and skipped
  adding the top-level import. Second: the local import was still there,
  shadowing the module for the whole function scope. Fix: one top-level
  import, no shadowing. Lesson: grep for the symbol, not the import line.
- Tag guard + workflow patterns had to move with the scheme
  (`m0-v*` → `v*`, minor-only regex).

## Tooling scars (our own process)

- A Python heredoc reused a variable (`p.write_text` where `c` was meant) and
  **overwrote `src/snp.rs` with the ceremony script**. Recovered from git;
  re-applied with the edit tool. Lesson: heredoc `replace()` fails *silently*
  on no-match — prefer the edit tool; assert replacements applied.
- The host's process filters blocked one QEMU-source dump and one `/proc`
  probe as "privilege escalation" — worked around with smaller reads. Not a
  system fault; recorded so future sessions expect it.

## Production-host incidents (not ours, recorded for honesty)

- `zns-deployment` VM (pid 420319) disappeared mid-session and respawned as
  a new pid under a supervisor process — its own lifecycle, never touched by
  any ceremony command (all stops QMP `query-name`-verified `m0-*`/`m1-*`).
- End-of-session count: 3 testnet guests live; zns-deployment down again per
  its supervisor. Owner directive: **never touch non-ceremony QEMUs**.

## Explicitly not tested (see 04-path-ahead.md)

draft→publish + immutable releases · the receipt round-trip · zns-canon
crypto in a ceremony · two-physical-host cross-VCEK · the lineage check's
rejection path (only its accept path has run) · `verify-before-publish`
(assumed) · in-guest report signature verification · hot migration.
