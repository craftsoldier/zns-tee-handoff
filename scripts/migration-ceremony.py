#!/usr/bin/env python3
"""M0→M1 custody migration ceremony. Run as root on the isolated SNP host.

The relay is untrusted: it boots both guests with bidirectional serial
sockets and moves text between them. Every guest-side check happens in the
guests; the relay can censor (ceremony stalls, retryable) but never forge.

Phases (each idempotent-ish, in order):
  verify  TAG_M0 TAG_M1   verify both image releases against the GitHub API
  announce TAG_M0 TAG_M1  boot M0 (waits for handoff) and M1 (announces),
                          save the announcement for upload, print relay cmds
  handoff  TAG_M0 TAG_M1  requires the announcement uploaded to the m1 release;
                          feeds HANDOFF to M0, pipes the wrap to M1, captures
                          the new custody state, prints publish commands
  verify-m1 TAG_M0 TAG_M1 reboot M1 alone; expects recovery of the same seed
"""
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

if len(sys.argv) != 4 or sys.argv[1] not in ("verify", "announce", "handoff", "verify-m1"):
    raise SystemExit(__doc__)
PHASE, TAG_M0, TAG_M1 = sys.argv[1], sys.argv[2], sys.argv[3]
REPO = "craftsoldier/zns-tee-handoff"
API = f"https://api.github.com/repos/{REPO}/releases/tags"
ROOT = Path("/home/ubuntu/dh_tests/migration") / f"{TAG_M0}-to-{TAG_M1}"
ASSETS_M0, ASSETS_M1 = ROOT / "assets-m0", ROOT / "assets-m1"
RUNTIME = ROOT / "runtime"
BOOT_TIME = 90  # seconds per boot poll


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def api_json(url, accept):
    request = urllib.request.Request(url, headers={
        "User-Agent": "zns-migration-relay", "Accept": accept,
    })
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read())


def download_asset(release, name, directory):
    assets = {a["name"]: a for a in release["assets"]}
    require(name in assets, f"{release['tag_name']} has no asset {name}")
    digest = assets[name]["digest"]
    require(digest.startswith("sha256:"), f"no digest for {name}")
    request = urllib.request.Request(assets[name]["url"], headers={
        "User-Agent": "zns-migration-relay", "Accept": "application/octet-stream",
    })
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    with urllib.request.urlopen(request, timeout=300) as response:
        target.write_bytes(response.read())
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
    require(actual == digest[7:], f"digest mismatch: {name}")
    print(f"verified {release['tag_name']}/{name}")


def fetch_image_assets(tag, directory):
    release = api_json(f"{API}/{tag}", "application/vnd.github+json")
    require(release["tag_name"] == tag, "api returned a different tag")
    download_asset(release, "m0-initrd.img", directory)
    download_asset(release, "vmlinuz", directory)
    download_asset(release, "OVMF.amdsev.fd", directory)
    return release


def qmp_stop(sock_path, expected_name, pidfile):
    pid = int(pidfile.read_text())
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect(str(sock_path))
        stream = sock.makefile("rwb")
        json.loads(stream.readline())

        def command(name):
            stream.write((json.dumps({"execute": name}) + "\n").encode())
            stream.flush()
            while True:
                reply = json.loads(stream.readline())
                if "error" in reply:
                    raise RuntimeError(reply)
                if "return" in reply:
                    return reply["return"]

        command("qmp_capabilities")
        reported = command("query-name")["name"]
        require(reported == expected_name, f"refusing to stop unexpected VM {reported!r}")
        command("quit")
    for _ in range(100):
        if not Path(f"/proc/{pid}").exists():
            return
        time.sleep(0.1)
    raise RuntimeError("VM did not exit")


def boot(name, assets, console_socket, challenge=""):
    log = RUNTIME / f"{name}.log"
    qmp_path = RUNTIME / f"{name}.qmp"
    pidfile = RUNTIME / f"{name}.pid"
    append = f"console=ttyS0 rdinit=/init panic=-1 challenge={challenge}" if challenge \
        else "console=ttyS0 rdinit=/init panic=-1"
    run("nice", "-n", "10", "qemu-system-x86_64", "-name", name,
        "-enable-kvm", "-machine", "q35,confidential-guest-support=sev0,vmport=off",
        "-cpu", "host", "-smp", "2", "-m", "4G", "-object",
        "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,policy=0x30000",
        "-bios", str(assets / "OVMF.amdsev.fd"), "-kernel", str(assets / "vmlinuz"),
        "-initrd", str(assets / "m0-initrd.img"), "-append", append,
        "-nic", "user,model=virtio-net-pci",
        "-display", "none", "-monitor", "none",
        "-chardev", f"socket,id=ser0,path={console_socket},server=on,wait=off,logfile={log}",
        "-serial", "chardev:ser0",
        "-qmp", f"unix:{qmp_path},server=on,wait=off",
        "-pidfile", str(pidfile), "-daemonize", "-no-reboot")
    return log, qmp_path, pidfile


def wait_for(log, markers, timeout=BOOT_TIME):
    for _ in range(timeout):
        content = log.read_text(errors="replace") if log.exists() else ""
        if any(marker in content for marker in markers):
            return content
        time.sleep(2)
    raise RuntimeError(f"timeout waiting for {markers} in {log}")


def relay_block(source_socket, dest_socket, begin, end):
    """Read a BEGIN/END block from one console and write it to the other."""
    with socket.socket(socket.AF_UNIX) as src, socket.socket(socket.AF_UNIX) as dst:
        src.settimeout(5)
        src.connect(str(source_socket))
        dst.connect(str(dest_socket))
        stream = src.makefile("rwb")
        block, inside = [], False
        deadline = time.time() + 120
        while time.time() < deadline:
            line = stream.readline()
            if not line:
                time.sleep(0.5)
                continue
            text = line.decode(errors="replace").rstrip("\n")
            if text == begin:
                inside = True
                block = [text]
                continue
            if inside:
                block.append(text)
                if text == end:
                    break
        require(inside and block[-1] == end, f"did not capture {begin} block")
        payload = ("\n".join(block) + "\n").encode()
        dst.sendall(payload)
        return block


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def main():
    require(os.geteuid() == 0, "run as root on the isolated SNP test host")
    RUNTIME.mkdir(parents=True, exist_ok=True)

    if PHASE in ("announce", "handoff", "verify-m1"):
        fetch_image_assets(TAG_M0, ASSETS_M0)
    if PHASE in ("announce", "verify-m1"):
        fetch_image_assets(TAG_M1, ASSETS_M1)
    if PHASE == "verify":
        fetch_image_assets(TAG_M0, ASSETS_M0)
        fetch_image_assets(TAG_M1, ASSETS_M1)
        print("both image releases verified; ready for the ceremony")
        return

    if PHASE == "announce":
        challenge = secrets.token_hex(32)
        # Stop stale ceremony VMs from a previous attempt, name-checked.
        for vm, tag in (("m0", TAG_M0), ("m1", TAG_M1)):
            qmp = RUNTIME / f"{vm}-{tag}.qmp"
            pidfile = RUNTIME / f"{vm}-{tag}.pid"
            if qmp.exists() and pidfile.exists():
                try:
                    qmp_stop(qmp, f"{vm}-{tag}", pidfile)
                    print(f"stopped stale VM {vm}-{tag}")
                except Exception as error:
                    print(f"could not stop stale {vm}-{tag}: {error}")
        log, qmp, pidfile = boot(f"m0-{TAG_M0}", ASSETS_M0, RUNTIME / "m0.console")
        wait_for(log, ["m0_handoff_listening", "M0_TEST_FAILED"])
        require("m0_handoff_listening" in log.read_text(errors="replace"),
                "M0 did not reach handoff-listen; check log")
        print("M0 resurrected and listening")
        log1, qmp1, pidfile1 = boot(f"m1-{TAG_M1}", ASSETS_M1, RUNTIME / "m1.console")
        wait_for(log1, ["ANNOUNCE_END", "M0_TEST_FAILED"])
        content = log1.read_text(errors="replace")
        require("ANNOUNCE_BEGIN" in content and "ANNOUNCE_END" in content,
                "M1 did not announce")
        announcement = "\n".join(content.splitlines()[
            content.splitlines().index("ANNOUNCE_BEGIN"):
            content.splitlines().index("ANNOUNCE_END") + 1])
        (RUNTIME / "announcement.txt").write_text(announcement + "\n")
        print("M1 announced and stays RUNNING (it holds the wrap key)")
        print("RELAY NOW (authenticated machine):")
        print(f"  scp {ROOT}/runtime/announcement.txt .")
        print(f"  gh release upload {TAG_M1} announcement.txt --repo {REPO}")
        print("then run: sudo python3 scripts/migration-ceremony.py handoff "
              f"{TAG_M0} {TAG_M1}")
        return

    if PHASE == "handoff":
        console_m0 = RUNTIME / "m0.console"
        console_m1 = RUNTIME / "m1.console"
        announcement = (RUNTIME / "announcement.txt").read_text()
        require(announcement.startswith("ANNOUNCE_BEGIN"), "saved announcement invalid")

        # Trigger M0 and feed it the announcement from the m1 release.
        with socket.socket(socket.AF_UNIX) as dst:
            dst.settimeout(5)
            dst.connect(str(console_m0))
            dst.sendall(f"HANDOFF {TAG_M1}\n".encode())
            dst.sendall(announcement.encode())
        print("HANDOFF + announcement fed to M0; waiting for the wrap")

        def capture(log, begin, end, timeout=180):
            log = Path(log)
            for _ in range(timeout):
                content = log.read_text(errors="replace") if log.exists() else ""
                if begin in content and end in content:
                    lines = content.splitlines()
                    return "\n".join(lines[lines.index(begin):lines.index(end) + 1])
                time.sleep(2)
            raise RuntimeError(f"timeout waiting for {begin}")

        wrap = capture(RUNTIME / f"m0-{TAG_M0}.log", "WRAP_BEGIN", "WRAP_END")
        print("wrap captured from M0; relaying to M1")
        with socket.socket(socket.AF_UNIX) as dst:
            dst.settimeout(5)
            dst.connect(str(console_m1))
            dst.sendall((wrap + "\n").encode())
        print("wrap relayed to M1; waiting for the new custody state")
        state_block = capture(RUNTIME / f"m1-{TAG_M1}.log",
                              "CUSTODY_STATE_BLOB_BEGIN", "CUSTODY_STATE_BLOB_END")
        (RUNTIME / "state").write_text(state_block + "\n")
        lines = state_block.splitlines()
        blob_hex = "".join(lines[1:-1])
        blob = bytes.fromhex(blob_hex)
        expected = blob[8:40].hex()
        print(f"M1 re-sealed the seed; new fingerprint {expected}; capture complete")
        print("RELAY NOW (authenticated machine):")
        print(f"  scp {RUNTIME}/state .")
        print(f"  gh release create custody-v2 --repo {REPO} --prerelease "
              f"--title 'custody state v2' --notes 'sealed by {TAG_M1}; "
              f"seed {expected}' state")
        qmp_stop(RUNTIME / f"m0-{TAG_M0}.qmp", f"m0-{TAG_M0}",
                 RUNTIME / f"m0-{TAG_M0}.pid")
        print("M0 stopped; its release remains bootable forever")
        return

    if PHASE == "verify-m1":
        custody = api_json(f"{API}/custody-v2", "application/vnd.github+json")
        assets = {a["name"]: a for a in custody["assets"]}
        require("state" in assets, "custody-v2 missing its state asset")
        request = urllib.request.Request(assets["state"]["url"], headers={
            "User-Agent": "zns-migration-relay", "Accept": "application/octet-stream",
        })
        with urllib.request.urlopen(request, timeout=120) as response:
            blob = response.read()
        digest = assets["state"]["digest"]
        require(digest.startswith("sha256:"), "custody-v2 digest missing")
        require(hashlib.sha256(blob).hexdigest() == digest[7:],
                "custody-v2 digest mismatch")
        expected = blob[8:40].hex()
        challenge = secrets.token_hex(32)
        log, qmp, pidfile = boot(f"m1-{TAG_M1}", ASSETS_M1,
                                 RUNTIME / "m1-verify.console", challenge)
        wait_for(log, ["M0_TEST_COMPLETE", "M0_TEST_FAILED"])
        content = log.read_text(errors="replace")
        require("state_recovered=ok" in content, "M1 did not recover custody-v2")
        require("release_self_check=accept" in content, "self-check not accepted")
        values = [l.split("=", 1)[1] for l in content.splitlines()
                  if l.startswith("dummy_seed_sha256=")]
        require(values, "no seed fingerprint in log")
        require(values[-1] == expected, "seed fingerprint does not match custody-v2")
        qmp_stop(qmp, f"m1-{TAG_M1}", pidfile)
        print(f"MIGRATION VERIFIED: seed {values[-1]} now custodied by {TAG_M1}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"MIGRATION {PHASE.upper()} FAILED: {error}")
        sys.exit(1)
