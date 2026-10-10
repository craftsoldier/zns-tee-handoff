# The Model

SEV-SNP guests hold a seed phrase that must never exist outside TEE RAM.
Custody of the seed moves between *generations* of measured guest images while
the host, the relay, and the public only ever see ciphertext. This document is
the trust model — the axioms everything else stands on.

## Axioms (owner-settled, 2026-10-10)

| Trusted | Untrusted |
| --- | --- |
| **GitHub** — always, unconditionally: releases, Actions, attestations | **The host** — may be malicious; may type anything, swap any file, proxy any console view, kill any VM |
| **The operator + their Mac** — the only GitHub writer; gh credentials never touch the TEE host | **Everyone else** — the public reads the store, nothing more |
| **The AMD chip** — SNP RAM, derived keys, VCEK reports | |

Accepted and unfixable: the host can always **deny** (kill VMs, cut wires).
Hardware buys confidentiality, never liveness.

## Model 1: the store is the custodian

- **GitHub releases are the sole authority and the sole store.** No guest has a
  disk; VMs are disposable; a custodian image is bootable forever.
- **Guests are read-only on GitHub.** Anonymous TLS GETs, digest checks, no
  credentials in-guest, ever. The guest TCB never contains the *concept* of a
  GitHub secret.
- **The operator is the sole writer** — the pen (`gh release upload/edit`),
  the trigger (`MIGRATION vX.Y.Z` typed on a console), and the verification
  step before every publish (`verify-before-publish`, see security doc).
- Every store mutation is a human, authenticated, attributable act.

Flow conservation: guests consume from the store and emit to the console; the
operator consumes from consoles and emits to the store. The operator is a
courier of ciphertext and public data, never of authority.

## Tags are custody generations

| Tag | Meaning |
| --- | --- |
| `vX.Y.0` | image of generation `X`; minor-only, machine-enforced by the workflow (patch tags would falsely claim measurement continuity) |
| `v1.x` | generation 1: the genesis custodian |
| `v2.x+` | successor generations **until they hold custody** — a successor that takes custody becomes the custodian for the next generation |
| `custody-vN` | the sealed state after `N−1` migrations; asset `state` = 168-byte `LNST0001` blob |

Every image change is a new measurement ⇒ a new release ⇒ a new generation or
minor. The chain extends indefinitely: `v3.0.0` someday needs only a new tag
and `MIGRATION v3.0.0`.

## Sealing: chip at rest, ARK in motion

| Path | Binding | Why |
| --- | --- | --- |
| Recovery (seed at rest) | `chipkey = PSP-derived(chip ⊕ measurement ⊕ policy)` — same chip only | the store is **public**; the chip anchor is the only thing converting public bytes into custody. A "measurement-only" seal would be openable by anyone who can download the image. |
| Ceremony (seed in motion) | reports verified against the **AMD ARK root** — any chip's VCEK verifies | migration is machine-agnostic; cross-host moves are structural |

## Why no Sigstore in the guest

Under the axioms (GitHub trusted + CI-only publishing + immutable releases),
"what's on the published release" *is* "what the workflow built." In-guest
Sigstore verifies against nobody. Attestations survive as public audit
receipts (`gh release verify`), not gates. Cost of this position: ~25k lines
of dependency code never enters the measured image.

## The one-sentence summary

**The store is law, the chip is the seal, the console is the trigger, and the
operator is the only hand that touches the pen.**
