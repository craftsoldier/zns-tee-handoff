# Operations Reference

Day-to-day mechanics: consoles, QEMU, artifacts, rate limits, discipline.

## The console layering (memorize this picture)

```
operator's Mac
  │ ssh zns                       ← ssh TO THE HOST (host runs sshd)
  ▼
host: socat / ceremony script     ← the socket is a FILE on the host fs
  ▼
unix socket → QEMU chardev → emulated UART → guest tty → stdin
                                                       (guest prints come
                                                        back the same socket)
```

- The guest has **no ssh, no listener**; it reads stdin and writes stdout.
- The socket is **QEMU's**, chosen at launch by whoever writes the command
  line. Guests are console-agnostic.
- Both directions ride one persistent connection — send the trigger, read the
  blocks back.
- Cross-host: ssh to each host separately; wrap bytes travel between consoles
  in the operator's clipboard (they are public-safe ciphertext). Never raw
  TCP chardevs; tunnel or carry instead.

Manual console session:

```
ssh zns
socat - UNIX-CONNECT:/home/ubuntu/dh_tests/migration/runtime/m0.console
# your terminal IS the console now: type  MIGRATION v2.0.0  and watch
```

## Backend choice per role

| Role | Backend | Why |
| --- | --- | --- |
| production mint | `-serial null` | armed listener unreachable; nothing to burn |
| ceremony guests | `-chardev socket,…,server=on,wait=off` + `logfile=` | local-only; log is human transcript, never parsed as data |
| cross-host | ssh-tunnel the unix socket | reachability collapses into ssh keys |

## Proven QEMU launch (ceremony guest)

```
qemu-system-x86_64 -name <name> -enable-kvm \
  -machine q35,confidential-guest-support=sev0,vmport=off \
  -cpu host -smp 2 -m 4G \
  -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,policy=0x30000 \
  -bios <assets>/OVMF.amdsev.fd -kernel <assets>/vmlinuz -initrd <assets>/m0-initrd.img \
  -append "console=ttyS0 rdinit=/init panic=-1" \
  -nic user,model=virtio-net-pci -display none -monitor none \
  -chardev socket,id=ser0,path=<runtime>/<n>.console,server=on,wait=off,logfile=<runtime>/<n>.log \
  -serial chardev:ser0 \
  -qmp unix:<runtime>/<n>.qmp,server=on,wait=off \
  -pidfile <runtime>/<n>.pid -daemonize -no-reboot
```

## Console markers (match on completed lines only)

`m0_state_created=ok` · `m0_migration_armed=ok` · `m0_migration_ignored=ok` ·
`m0_migration_complete=ok` · `m0_migration_error=…` · `m0_stand_down=ok` ·
`m1_announced=ok` · `m1_wrap_noise=ok` · `m1_wrap_error=…` ·
`m1_lineage_mismatch=ok` · `m1_custody_taken=ok` · `state_recovered=ok` ·
`release_self_check=accept` — plus the delimited blocks
`GENESIS_STATE_BLOB`, `ANNOUNCE`, `WRAP`, `CUSTODY_STATE_BLOB`.

## Artifact quick reference

| Thing | Where |
| --- | --- |
| seed fingerprint (public) | custody blob bytes `[8..40]` |
| sealed-for measurement (public) | custody blob bytes `[40..88]` |
| expected successor measurement | `snp-measurement.txt` asset on the successor release |
| Q + VCEK report | `announcement.txt` (report = 1184-byte SNP attestation; `report_data = H(Q)`; VCEK cert NOT included — fetched from AMD KDS by `chip_id` during verification) |
| wrap layout | `MIGW0001 ‖ fingerprint(32) ‖ H(Q)(32) ‖ H(E)(32)` header (AAD) ‖ nonce ‖ ct ‖ tag |

## The operator ritual (publish path)

```
1. scp <artifact> from the host          (transit through hostile ground is fine)
2. verify-before-publish ON THE MAC      (announcement: sig→ARK/measure/Q-bind;
                                           blob: magic/fp-continuity/sealed-for-successor)
                                           — DEFERRED TOOL: currently assumed
3. gh release upload / create            (only on PASS; fail = nothing published)
```

## Limits and discipline

- **GitHub anonymous API: 60 req/hr per host IP** — guests and relay share
  it; run each ceremony phase once; a full ceremony ≈ 45 calls.
- **VM stops**: only via each VM's own QMP socket after `query-name`
  verification. Production zns guests are never touched — 3 testnet +
  zns-deployment (which has its own supervisor lifecycle; leave it alone).
- **One handoff per boot**: after `m0_migration_complete` the listener exits;
  a reboot re-arms via recovery (proven). The hostile host can burn this —
  accepted (subsumed by kill power).
- **Logfiles are best-effort artifacts** (QEMU drops/dups bytes under
  pressure) — never a data channel; the socket stream is the only truth.
- **Immutable releases retire tag names** (anti-resurrection): rehearsal
  lineages number upward (`v1.1.0`, `v2.1.0`), never re-cut.
