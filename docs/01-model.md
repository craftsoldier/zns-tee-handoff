# The Model

SEV-SNP guests hold a seed phrase that must never exist outside TEE RAM.
Custody of the seed moves between *generations* of measured guest images while
the host, the relay, and the public only ever see ciphertext. This document is
the trust model — the axioms, the principles, and the reasoning behind every
design decision. It is the "why"; the ceremony doc is the "how".

## Axioms (owner-settled, 2026-10-10)

| Trusted | Untrusted |
| --- | --- |
| **GitHub** — always, unconditionally: releases, Actions, attestations. "Nothing will happen to GitHub no matter what." | **The host** — may be malicious; may type anything into any console, swap any file, proxy any console view, run the relay, kill any VM |
| **The operator + their Mac** — the only GitHub writer; gh credentials never touch the TEE host | **Everyone else** — the public reads the store, nothing more |
| **The AMD chip** — SNP RAM, derived keys, VCEK reports, the ARK root | |

Accepted and unfixable: the host can always **deny** (kill VMs, cut wires,
garble channels). Hardware buys confidentiality, never liveness. A hostage
seed is a bad day; a leaked seed is game over — that is the trade, taken
deliberately.

## Model 1: the store is the custodian

- **GitHub releases are the sole authority and the sole store.** No guest has
  a disk; VMs are disposable; a custodian image is bootable forever, so the
  migration window never closes.
- **Guests are read-only on GitHub.** Anonymous TLS GETs, digest checks, no
  credentials in-guest. The guest TCB never contains the *concept* of a
  GitHub secret, so there is nothing to exfiltrate or abuse.
- **The operator is the sole writer** — the pen (`gh release upload/edit`),
  the trigger (`MIGRATION vX.Y.Z` typed on a console), and the verification
  step before every publish.
- Every store mutation is a human, authenticated, attributable act. The
  store's write surface is exactly as wide as the ceremony's decision surface.

Flow conservation:

```
                    GITHUB (trusted store)
                    reads ↑        writes ↑
                          │              │
                     guests           operator
                          │              │
                    console ←────────────┘
                    (prints)   operator reads blocks, types trigger,
                               carries public-safe artifacts
```

Guests consume from the store and emit to the console; the operator consumes
from consoles and emits to the store. The operator is a courier of ciphertext
and public data — **never an authority**.

## The deputy principle (the campaign's core lesson)

A trusted store only guarantees *"these are the bytes that were uploaded."*
It says nothing about whether the bytes were **true when uploaded**. Every
artifact that reaches the store through hostile territory needs something the
hostility cannot forge — a signature — or the store launders the lie into law.

The confused-deputy family (H001–H003) all had this shape: the attacker never
touches GitHub; the operator carries their bytes in with valid credentials.
The defense is not vigilance (a hostile host renders the operator's display —
console views, file listings, relay output are all host software), it is
verification on ground the host doesn't own: **the Mac, against public roots**.
`verify-before-publish` is the ritual's code; until it exists, the model holds
by assumption.

## Physics vs authorization (the cleanest split in the design)

| Layer | Decides | Mechanism |
| --- | --- | --- |
| **Guest** | *physics only*: "who am I, where does the seed go" | live measurement vs report vs store headers; the seal |
| **Operator + GitHub** | *what is sanctioned* | which release exists, which trigger is typed, what gets published |
| **Audit layer** | *what anyone can later prove* | release attestations (`gh release verify`) — receipts, not gates |

Guests never make trust decisions; the operator never makes physics
decisions. Every gap we ever found lived in the seam where one layer was
doing the other's job.

## Tags are custody generations

| Tag | Meaning |
| --- | --- |
| `vX.Y.0` | image of generation `X`; minor-only, machine-enforced (patch tags would falsely claim measurement continuity) |
| `v1.x` | generation 1: the genesis custodian |
| `v2.x+` | successor generations **until they hold custody** — a successor that takes custody becomes the custodian for the next generation |
| `custody-vN` | sealed state after `N−1` migrations; the lineage IS the store's history |

The chain extends indefinitely: `v3.0.0` someday needs only a tag and
`MIGRATION v3.0.0`. The trigger names the next generation only
(`major == mine + 1`) — linearity by construction, and the tag only *names*:
authorization data is fetched from inside the named release, never injected
through the console.

## Sealing: chip at rest, ARK in motion

| Path | Binding | Why |
| --- | --- | --- |
| Recovery (at rest) | `chipkey = PSP-derived(chip ⊕ measurement ⊕ policy)` — same chip only | the store is **public**; trusting GitHub ≠ trusting everyone who can *download*. The chip anchor is the only thing converting public bytes into custody. A "measurement-only" seal is openable by anyone on earth with the release. |
| Ceremony (in motion) | reports verified against the **AMD ARK root** — any chip's VCEK | migration is machine-agnostic; cross-host moves are structural, not configured |

Corollary: the seal cannot be made VCEK-independent, ever — that is not a
GitHub-trust question, it is an information-theoretic one. Machine
independence at *rest* would require either a public key in the store (anyone
decrypts) or a human-held key (trust moves from silicon to a person). Neither
is acceptable; therefore **migrate before decommissioning** is the one
operational rule the physics imposes.

## The chip-identity dial

ARK-only verification = "any genuine chip running the real image" — the
machine-agnostic default, required for cross-host custody. Every SNP report
also carries a **signature-covered `chip_id`**: one comparison
(`successor.chip_id == custodian.chip_id`) turns the ceremony into
same-machine enforcement, killing even a *pinned* attacker announcement from
another host. Choose per ceremony; both are one `if` apart.

## Why no Sigstore in the guest

Under the axioms (GitHub trusted + CI-only publishing + immutable releases),
"what's on the published release" *is* "what the workflow built." In-guest
Sigstore verifies against nobody — its two real adversaries (malicious host
mounting files; forged release via leaked token) are both handled by
self-fetch + immutability + governance instead. The position costs ~25k lines
of dependency code that never enter the measured image, and the attestations
survive as public audit receipts.

For contrast, zns-migrate's mount-based model is the right shape for the
*opposite* axioms (host untrusted, guest network-isolated): host-mounted
papers + in-guest bundle verification. The repos are independent learning
projects; the model here chose store-authority + egress-to-one-destination.

## Fail-safe as a design language

- Garbage on any console → ignored; the custodian remains standing.
- Trigger before publish → anonymous fetch 404s → no-op.
- Wrong-key wrap → decrypt fails → discarded, session keeps waiting.
- Wrong-seed wrap → lineage fingerprint mismatch → discarded.
- One handoff per boot → a burned listener is a reboot, not a loss.
- Orphan wraps (dead Q) → useless ciphertext forever; replays only stall.
- Poisoned custody blob → fails closed at the next boot (unopenable ≠ stolen).

Nothing the host can do moves the seed anywhere useful. The worst outcomes
are stalls and reboots — priced in.

## What each party can never do (the wall)

| Party | Can never |
| --- | --- |
| Host | read guest RAM; forge a VCEK report; unseal a foreign-measurement blob; decrypt any wrap; change what a fetch returns (TLS) |
| Public / relay | anything the host can't, plus: write GitHub; see plaintext seed anywhere, ever |
| GitHub (trusted, but bounded) | read the seed (everything stored is ciphertext or public headers) |
| Operator | extract the seed (no command exists that prints it; exits are seal + pinned-Q wrap only) |

The seed's only exits from any guest: **chipkey-sealed ciphertext** or
**ECIES wrap to a release-pinned, report-bound Q**. This property survived a
full adversarial campaign (see 03-security-campaign.md).

## Air-gap asymmetry

M1's only ceremony input is the wrap — public-safe ciphertext addressed to
its ephemeral key — so **the successor side can run fully offline**:
announcement out its console, wrap in its console, custody blob out its
console. The network leg that must exist is M0 → GitHub, because M0's inputs
are *decisions*, and decisions may only arrive from the store. One sentence:
**M0's inputs must come from the store because they authorize; M1's inputs
may come from anywhere because they're ciphertext.**

## Cold over hot

The production mint carries **no console and no ceremony surface**.
Migration is cold: stop mint → boot a disposable ceremony custodian from
custody-vN (it holds the console) → `MIGRATION` → custody-v(N+1) → boot the
new mint. Zero-downtime "hot" migration was designed but never built;
minutes of accepted downtime buys a mint image that is unreachable by
construction. Rehearsed alternatives exist because recovery is proven: any
custodian boot re-arms, forever.

## The one-sentence summary

**The store is law, the chip is the seal, the console is the trigger, and the
operator is the only hand that touches the pen.**
