# The Path Ahead

The repos are independent learning projects; **patterns transfer, code does
not.** No pattern ships to a zns repo without a green rehearsal behind it in
this lab. Order: zns-canon first (the foundation), then migrate/deployment in
parallel, then mint.

## Stage 0 — rehearsals in this lab (before any PR)

| # | Rehearsal | Status |
| --- | --- | --- |
| R1 | flip immutable releases + `v*` tag ruleset on this repo; probe the edges (human token rejected at the tag; published asset un-clobberable) | not run |
| R2 | **draft→publish ceremony** — the biggest untested piece: `release.yml --draft`, boot M1 from draft, attach announcement, publish, trigger | not run |
| R3 | lineage-check negative fire: foreign-seed wrap to a real Q → `m1_lineage_mismatch` must fire | not run (check passed silently in both ceremonies) |
| R4 | cross-machine operator rehearsal: two runtimes, operator carries wrap bytes by hand | not run |

## Stage 1 — zns-canon (the foundation)

| PR | Content |
| --- | --- |
| `store.rs` | GitHub release client from this repo's `verify.rs`: fetch-by-tag, digest-verified assets, rate-limit discipline (~150 lines, hardware-proven) |
| custody record | public fixed-offset header (`fingerprint` + `sealed_for` + policy) on the capsule — readable by anyone, unsealable by anyone; `fingerprint_of`/`blob_measurement` helpers |
| migration wrap | fill the "not implemented" hole: header-as-AAD binding, unwrap fingerprint checks, lineage check (curve choice theirs; structure ours) |
| delete Sigstore | remove `sigstore-verify`/`sigstore-trust-root` from the guest tree (≈ −600 first-party lines, ≈ −25k dependency lines from the measured image) |

Keep: `attestation.rs` ARK verification (they are ahead of us — it is the
missing in-guest signature check), capsules, X25519, sealing seam.

## Stage 2 — zns-migrate and zns-deployment

**zns-migrate**: self-fetch (drop the three host-mounted files), no in-guest
Sigstore, emergent roles from the store, armed listener + console trigger,
keep the receipt round-trip and capsules. The CLI reduces to a fixed verb —
every argument it answered becomes a store-derived fact.

**zns-deployment**: `release.yml` publishes DRAFT; immutable releases + tag
ruleset (Actions-only `v*`); CI-App-only publishing; the runbook gains the
ceremony steps (publish = the commit point).

**zns-mint**: **cold migration only** — the mint needs no console socket.
Migration = stop mint → boot a disposable ceremony custodian from custody-vN
(it has the console) → `MIGRATION` → custody-v(N+1) → boot new mint. Zero
downtime ("hot") was never built; minutes of accepted downtime buys a mint
image with no ceremony surface at all.

## The known gap list (each needs its own MIGRATION VERIFIED moment)

1. draft→publish + immutability — designed, never executed (R1/R2)
2. the receipt round-trip — zns-migrate's idea; never built here
3. zns-canon crypto formats in a real ceremony — ceremony proven on p256/LNST, not on their stack
4. true cross-VCEK on two physical hosts — protocol is machine-agnostic; hardware never available
5. `verify-before-publish` — assumed to exist; ~130 lines when assumption becomes code
6. in-guest report signature verification — zns-canon has it; this repo does not

## The destination

A fresh lineage under v1.1.0/v2.1.0 (immutability retires tag names) with the
**real ZNS seed**: genesis inside the TEE, one ceremony per upgrade, an
append-only public ledger of custody, and the seed never existing outside
guest RAM.
