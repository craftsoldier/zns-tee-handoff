#!/usr/bin/env python3
"""MIGRATION m1-v0.2.0 — M0→M1 custody handoff ceremony.

Run as root on the isolated SNP test host. The relay (this script, run by the
untrusted host operator) only moves text between guest consoles and GitHub
releases. Every security check happens inside the guests. VMs are stopped
only via their own QMP sockets after a name check.

Usage, in order:
  migration-ceremony.py verify              verify both image releases
  migration-ceremony.py genesis TAG_M0      boot M0: fresh seed -> custody-v1
  migration-ceremony.py announce TAG_M0 TAG_M1
                                            boot M1: announce (M1 stays running)
  migration-ceremony.py handoff TAG_M0 TAG_M1
                                            trigger M0, relay wrap to M1,
                                            capture custody-v2, stop M0 and M1
  migration-ceremony.py verify-m1 TAG_M0 TAG_M1
                                            fresh M1 boot recovers custody-v2
"""
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

if len(sys.argv) < 3 or sys.argv[1] not in ("verify", "genesis", "announce", "handoff", "verify-m1"):
    raise SystemExit(__doc__)
PHASE = sys.argv[1]
TAG_M0 = sys.argv[2] if len(sys.argv) > 2 else ""
TAG_M1 = sys.argv[3] if len(sys.argv) > 3 else ""
REPO = "craftsoldier/zns-tee-handoff"
API = f"https://api.github.com/repos/{REPO}/releases/tags"
ROOT = Path("/home/ubuntu/dh_tests/migration")
ASSETS_M0 = ROOT / "assets-m0"
ASSETS_M1 = ROOT / "assets-m1"
RUNTIME = ROOT / "runtime"
NAME_M0 = f"m0-{TAG_M0}"
NAME_M1 = f"m1-{TAG_M1}"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def api_json(url, accept):
    request = urllib.request.Request(url, headers={
        "User-Agent": "zns-migration-relay", "Accept": accept,
    })
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read())


def fetch_release(tag):
    release = api_json(f"{API}/{tag}", "application/vnd.github+json")
    require(release.get("tag_name") == tag, "api returned a different tag")
    return release


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


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def qmp_stop(qmp_path, expected_name, pidfile):
    pid = int(pidfile.read_text())
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect(str(qmp_path))
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


def boot(name, assets, console_socket, log):
    run("nice", "-n", "10", "qemu-system-x86_64", "-name", name,
        "-enable-kvm", "-machine", "q35,confidential-guest-support=sev0,vmport=off",
        "-cpu", "host", "-smp", "2", "-m", "4G", "-object",
        "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,policy=0x30000",
        "-bios", str(assets / "OVMF.amdsev.fd"), "-kernel", str(assets / "vmlinuz"),
        "-initrd", str(assets / "m0-initrd.img"),
        "-append", "console=ttyS0 rdinit=/init panic=-1",
        "-nic", "user,model=virtio-net-pci",
        "-display", "none", "-monitor", "none",
        "-chardev", f"socket,id=ser0,path={console_socket},server=on,wait=off,logfile={log}",
        "-serial", "chardev:ser0",
        "-qmp", f"unix:{RUNTIME / (name + '.qmp')},server=on,wait=off",
        "-pidfile", str(RUNTIME / (name + ".pid")), "-daemonize", "-no-reboot")


def wait_for(path, marker, timeout=180):
    log = Path(path)
    for _ in range(timeout // 2):
        content = log.read_text(errors="replace") if log.exists() else ""
        if marker in content:
            return content
        time.sleep(2)
    raise RuntimeError(f"timeout waiting for {marker!r} in {log}")


def poll_block(path, begin, end, timeout):
    """Poll a log file until a BEGIN/END block exists, then return it."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        content = Path(path).read_text(errors="replace") if Path(path).exists() else ""
        lines = content.splitlines()
        if begin in lines and end in lines:
            return "\n".join(lines[lines.index(begin):lines.index(end) + 1])
        time.sleep(2)
    raise RuntimeError(f"timeout waiting for {begin!r} in {path}")


def fingerprint(log):
    values = [line.split("=", 1)[1] for line in Path(log).read_text(errors="replace").splitlines()
              if line.startswith("dummy_seed_sha256=")]
    require(values, f"no seed fingerprint in {log}")
    return values[-1]


def phase_verify():
    release_m0 = fetch_release(TAG_M0)
    download_asset(release_m0, "m0-initrd.img", ASSETS_M0)
    download_asset(release_m0, "vmlinuz", ASSETS_M0)
    download_asset(release_m0, "OVMF.amdsev.fd", ASSETS_M0)
    release_m1 = fetch_release(TAG_M1)
    download_asset(release_m1, "m0-initrd.img", ASSETS_M1)
    download_asset(release_m1, "vmlinuz", ASSETS_M1)
    download_asset(release_m1, "OVMF.amdsev.fd", ASSETS_M1)
    print("both image releases verified; ready for the ceremony")


def phase_genesis():
    try:
        fetch_release("custody-v1")
        raise RuntimeError("custody-v1 already exists; delete it to start a fresh lineage")
    except urllib.error.HTTPError as error:
        require(error.code == 404, f"unexpected api status {error.code}")
    release = fetch_release(TAG_M0)
    download_asset(release, "m0-initrd.img", ASSETS_M0)
    download_asset(release, "vmlinuz", ASSETS_M0)
    download_asset(release, "OVMF.amdsev.fd", ASSETS_M0)
    challenge = secrets.token_hex(32)
    log = RUNTIME / "m0.log"
    boot(NAME_M0, ASSETS_M0, RUNTIME / "m0.console", log)
    content = wait_for(log, "m0_state_created=ok")
    require("release_self_check=accept" in content, "self-check not accepted")
    require("GENESIS_STATE_BLOB_END" in content, "no genesis blob")
    lines = content.splitlines()
    blob = bytes.fromhex("".join(
        lines[lines.index("GENESIS_STATE_BLOB_BEGIN") + 1:
               lines.index("GENESIS_STATE_BLOB_END")]))
    require(blob[:8] == b"LNST0001", "bad state magic")
    (RUNTIME / "state").write_bytes(blob)
    print(f"genesis ok: seed {fingerprint(log)}; M0 stays RUNNING (handoff armed)")
    print("RELAY NOW (authenticated machine):")
    print(f"  scp {RUNTIME}/state .")
    print(f"  gh release create custody-v1 --repo {REPO} --prerelease "
          f"--title 'custody state v1' --notes 'seed {fingerprint(content)}' state")
    print(f"then run: migration-ceremony.py announce {TAG_M0} {TAG_M1}")


def phase_announce():
    require(fetch_release("custody-v1").get("tag_name") == "custody-v1",
            "custody-v1 must exist before the successor announces")
    release = fetch_release(TAG_M1)
    download_asset(release, "m0-initrd.img", ASSETS_M1)
    download_asset(release, "vmlinuz", ASSETS_M1)
    download_asset(release, "OVMF.amdsev.fd", ASSETS_M1)
    log = RUNTIME / "m1.log"
    boot(NAME_M1, ASSETS_M1, RUNTIME / "m1.console", log)
    content = wait_for(log, "ANNOUNCE_END")
    require("m1_announced=ok" in content, "M1 did not announce")
    lines = content.splitlines()
    announce = "\n".join(lines[lines.index("ANNOUNCE_BEGIN"):
                              lines.index("ANNOUNCE_END") + 1])
    (RUNTIME / "announcement.txt").write_text(announce + "\n")
    print("M1 announced and stays RUNNING (it holds the wrap key)")
    print("RELAY NOW (authenticated machine):")
    print(f"  scp {RUNTIME}/announcement.txt .")
    print(f"  gh release upload {TAG_M1} announcement.txt --repo {REPO}")
    print(f"then run: migration-ceremony.py handoff {TAG_M0} {TAG_M1}")


def phase_handoff():
    require(fetch_release("custody-v1").get("tag_name") == "custody-v1",
            "custody-v1 must exist")
    release = fetch_release(TAG_M1)
    assets = {a["name"]: a for a in release["assets"]}
    require("announcement.txt" in assets,
            f"upload announcement.txt to {TAG_M1} first")
    console_m0 = RUNTIME / "m0.console"
    require(console_m0.exists(), "M0 console socket missing; run genesis phase")
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5)
        s.connect(str(console_m0))
        s.sendall(f"HANDOFF {TAG_M1}\n".encode())
    print("HANDOFF trigger sent to M0; waiting for the wrap")
    wrap = poll_block(RUNTIME / "m0.log", "WRAP_BEGIN", "WRAP_END", 180)
    print("wrap captured from M0; relaying to M1")
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(5)
        s.connect(str(RUNTIME / "m1.console"))
        s.sendall((wrap + "\n").encode())
    print("wrap relayed to M1; waiting for the new custody state")
    state_block = poll_block(RUNTIME / "m1.log",
                             "CUSTODY_STATE_BLOB_BEGIN",
                             "CUSTODY_STATE_BLOB_END", 180)
    (RUNTIME / "state").write_text(state_block + "\n")
    import re
    match = re.search(r"dummy_seed_sha256=([0-9a-f]{64})", state_block)
    require(match is not None, "no fingerprint in custody state")
    print(f"M1 re-sealed the seed: {match.group(1)}")
    print("RELAY NOW (authenticated machine):")
    print(f"  scp {RUNTIME}/state .")
    print(f"  gh release create custody-v2 --repo {REPO} --prerelease "
          f"--title 'custody state v2' --notes 'sealed by {TAG_M1}; "
          f"seed {match.group(1)}' state")
    qmp_stop(RUNTIME / "m0.qmp", NAME_M0, RUNTIME / "m0.pid")
    print("M0 stopped (name-checked); its release remains bootable forever")


def phase_verify_m1():
    custody = fetch_release("custody-v2")
    assets = {a["name"]: a for a in custody["assets"]}
    require("state" in assets, "custody-v2 has no state asset")
    request = urllib.request.Request(assets["state"]["url"], headers={
        "User-Agent": "zns-migration-relay", "Accept": "application/octet-stream",
    })
    with urllib.request.urlopen(request, timeout=120) as response:
        blob = response.read()
    digest = assets["state"]["digest"]
    require(digest.startswith("sha256:"), "custody-v2 digest missing")
    require(hashlib.sha256(blob).hexdigest() == digest[7:], "digest mismatch")
    expected = blob[8:40].hex()
    log = RUNTIME / "m1-verify.log"
    boot(NAME_M1, ASSETS_M1, RUNTIME / "m1-verify.console", log)
    content = wait_for(log, "state_recovered=ok")
    require("release_self_check=accept" in content, "self-check not accepted")
    values = [line.split("=", 1)[1] for line in content.splitlines()
              if line.startswith("dummy_seed_sha256=")]
    require(values and values[-1] == expected,
            f"fingerprint mismatch: expected {expected}")
    qmp_stop(RUNTIME / "m1.qmp", NAME_M1, RUNTIME / "m1.pid")
    print(f"MIGRATION VERIFIED: seed {values[-1]} recovered by {TAG_M1}")


if __name__ == "__main__":
    try:
        require(os.geteuid() == 0, "run as root on the isolated SNP test host")
        RUNTIME.mkdir(parents=True, exist_ok=True)
        {"verify": phase_verify, "genesis": phase_genesis, "announce": phase_announce,
         "handoff": phase_handoff, "verify-m1": phase_verify_m1}[PHASE]()
    except Exception as error:
        print(f"MIGRATION {PHASE.upper()} FAILED: {error}")
        sys.exit(1)
