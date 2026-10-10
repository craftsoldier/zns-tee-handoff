# The Adversarial Campaign (2026-10-10)

Sec-harness campaign: `state-zns-tee-handoff.json`. Threat model: **malicious
host without GitHub write access** — full console control both directions, VM
lifecycle, host filesystem, relay replacement, egress blocking (TLS prevents
modification, not denial). Cannot: write GitHub, forge VCEK reports, read SNP
RAM, decrypt wraps.

## Result: the core property HELD

> The seed exits a guest only as (a) chipkey-sealed ciphertext or (b) an ECIES
> wrap to a release-pinned, report-bound Q. **No seed-theft or custody-diversion
> path survived the campaign.**

Notably: no console command dumps seed material; booting the real image with
no custody state only creates a worthless fresh seed; every wrong-key or
wrong-seed wrap dies at M1's checks.

## The hypotheses and their verdicts

| ID | Attack | Verdict |
| --- | --- | --- |
| **H001** (critical) | **Announcement swap → seed theft.** Host replaces `announcement.txt` pre-upload with own Q + fabricated report (measurement copied from the public asset, `report_data = H(Q_mine)` — self-consistent). Operator pins it with their own credentials (confused deputy); trigger wraps the real seed to the attacker's plain key. No TEE, no GitHub access needed. | **killed by Mac-verification axiom** — verify the announcement's signature → VCEK (AMD KDS by chip_id) → ARK, signed measurement == release asset, `report_data == H(Q)` on the operator's clean machine before upload. Fabricated reports fail the signature host-independently. **The kill is procedural until the tool exists.** |
| **H002** (high) | **Custody blob substitution.** Host swaps `runtime/state` pre-publish; nastiest variant replays `custody-v1` as `custody-v2` (fingerprint continuity passes; sealed-for is wrong). | killed by the same axiom (blob check, below). Fail-closed at verify-m1 even without it. |
| **H003** (high) | **Echo-spoofed custody block.** Type a fake `CUSTODY_STATE_BLOB` into M1's console; the tty echo lands in the relay's captured stream; first-complete-block wins. | killed by the same axiom — the echo cannot forge a valid seal. |
| **H004** (medium) | **Armed-state burn.** Premature `MIGRATION` with a stale pinned announcement → orphan wrap → one-shot listener exits → forced mint reboot. | **rejected by subsumption**: the host can `kill -9` QEMU outright — strictly stronger, undefendable, same class. |

## The verification matrix (why checks kept going missing)

| Artifact | Guest-side (physics) | Mac-side before publish |
| --- | --- | --- |
| announcement | M0: measurement, policy, Q-binding (signature check **still missing in-guest** — docs claimed it; code never did) | **signature → ARK + measurement + Q-binding** |
| wrap | M1: decrypt + lineage fingerprint (added 2026-10-10) | n/a (never published) |
| custody blob | M1: sealed to own measurement by construction | **magic + fingerprint continuity + sealed-for-successor** |

Every late-caught gap was a Mac-side check — because guests are versioned and
reviewed while the publish ritual was bare `scp` + `gh`. The fix is one tool,
not vigilance:

```
verify-before-publish  (~130 lines, DEFERRED by owner decision — assumed to exist)
  announcement: sig→ARK, measurement, report_data==H(Q)
  blob:          magic, fp continuity vs custody-vN, sealed_for == successor measurement
```

## The chip-identity dial

ARK-only verification = "any genuine chip running the real image" (the
machine-agnostic default, required for cross-host migration). Every report
carries a **signature-covered `chip_id`** — one comparison
(`m1.chip_id == m0.chip_id`) turns it into same-machine enforcement. Choose
per ceremony; the dial is free.

## Honest residuals

- `verify-before-publish` does not exist yet — H001's kill is a promise until it does.
- In-guest report **signature verification** is absent (the deferred "item 3");
  zns-canon's `attestation.rs` has the tested implementation.
- A hostile host can always deny (kill/cut/garble) — accepted axiom.
