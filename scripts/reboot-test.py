#!/usr/bin/env python3
"""M0 reboot persistence test. Run as root on the isolated SNP test host.

Usage: reboot-test.py [TAG]     (default: m0-v0.7.0)

Downloads the tagged release from GitHub, verifies every asset digest, then
proves the seed survives across two boots on one state disk:
  boot 1: genesis + local recovery      (m0_created=ok must appear)
  boot 2: recovery only, fresh challenge (m0_created=ok must NOT appear)
Both boots must print release_self_check=accept and the same seed fingerprint.
Every VM is stopped only through its own QMP socket after the reported VM name
matches dh-<TAG>; nothing else on the host is ever signalled.
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

TAG = sys.argv[1] if len(sys.argv) > 1 else "m0-v0.7.0"
assert TAG.startswith("m0-v"), "tag must look like m0-vX.Y.Z"
REPO = "craftsoldier/zns-tee-handoff"
API = f"https://api.github.com/repos/{REPO}/releases/tags/{TAG}"
ROOT = Path("/home/ubuntu/dh_tests") / TAG
ASSETS, RUNTIME = ROOT / "assets", ROOT / "runtime"
DISK = ROOT / "reboot-state.img"
UUID = "df050000-0000-4000-8000-000000000005"
NAME = f"dh-{TAG}"
MEASUREMENT_ASSET = "snp-measurement.txt"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def api(url, accept):
    request = urllib.request.Request(url, headers={
        "User-Agent": "zns-custody-reboot-test", "Accept": accept,
    })
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def fetch_and_verify_assets():
    ASSETS.mkdir(parents=True, exist_ok=True)
    release = json.loads(api(API, "application/vnd.github+json"))
    require(release["tag_name"] == TAG, "api returned a different tag")
    for asset in release["assets"]:
        digest = asset["digest"]
        require(digest.startswith("sha256:"), f"no digest for {asset['name']}")
        target = ASSETS / asset["name"]
        target.write_bytes(api(asset["url"], "application/octet-stream"))
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        require(actual == digest[7:], f"digest mismatch: {asset['name']}")
        print(f"verified {asset['name']}")
    measurement = (ASSETS / MEASUREMENT_ASSET).read_text().strip()
    require(len(measurement) == 96, "malformed measurement file")
    return measurement


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def stop_vm(qmp_path, pidfile):
    """Quit the VM only if its own QMP socket reports the expected name."""
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
        require(reported == NAME, f"refusing to stop unexpected VM {reported!r}")
        command("quit")
    for _ in range(100):
        if not Path(f"/proc/{pid}").exists():
            return
        time.sleep(0.1)
    raise RuntimeError("test VM did not exit")


def write_flag(name, content):
    source = RUNTIME / name.strip("/")
    source.write_text(content)
    run("debugfs", "-w", "-R", f"write {source} /{name}", str(DISK))


def boot(number, challenge):
    if number > 1:
        run("debugfs", "-w", "-R", "rm /boot-challenge", str(DISK))
    write_flag("boot-challenge", challenge)
    log = RUNTIME / f"boot-{number}.log"
    qmp_path = RUNTIME / f"boot-{number}.qmp"
    pidfile = RUNTIME / f"boot-{number}.pid"
    run("nice", "-n", "10", "qemu-system-x86_64", "-name", NAME,
        "-enable-kvm", "-machine", "q35,confidential-guest-support=sev0,vmport=off",
        "-cpu", "host", "-smp", "2", "-m", "4G", "-object",
        "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,policy=0x30000",
        "-bios", str(ASSETS / "OVMF.amdsev.fd"), "-kernel", str(ASSETS / "vmlinuz"),
        "-initrd", str(ASSETS / "m0-initrd.img"),
        "-append", "console=ttyS0 rdinit=/init panic=-1",
        "-drive", f"file={DISK},if=virtio,format=raw",
        "-nic", "user,model=virtio-net-pci",
        "-display", "none", "-serial", f"file:{log}", "-monitor", "none",
        "-qmp", f"unix:{qmp_path},server=on,wait=off",
        "-pidfile", str(pidfile), "-daemonize", "-no-reboot")
    for _ in range(90):
        content = log.read_text(errors="replace") if log.exists() else ""
        if "M0_TEST_COMPLETE:" in content or "M0_TEST_FAILED:" in content:
            return content
        time.sleep(2)
    raise RuntimeError(f"boot {number} timed out")


def fingerprint(log):
    values = [line.split("=", 1)[1] for line in log.splitlines()
              if line.startswith("dummy_seed_sha256=")]
    require(len(values) >= 1, "no seed fingerprint in log")
    return values[-1]


def main():
    require(os.geteuid() == 0, "run as root on the isolated SNP test host")
    require(not DISK.exists(), f"{DISK} already exists; remove it to rerun")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    measurement = fetch_and_verify_assets()
    print(f"release measurement: {measurement}")

    with DISK.open("xb") as file:
        file.truncate(256 * 1024 * 1024)
    run("mkfs.ext4", "-F", "-U", UUID, "-L", "DH_REBOOT_TEST", str(DISK))
    write_flag("INIT_ALLOWED", "Dummy secrets only. First creation authorized.\n")

    first = boot(1, secrets.token_hex(32))
    require("M0_TEST_COMPLETE:" in first, "boot 1 failed")
    require("m0_created=ok" in first, "boot 1 did not create genesis")
    require("release_self_check=accept" in first, "boot 1 self-check not accepted")
    fingerprint_one = fingerprint(first)
    stop_vm(RUNTIME / "boot-1.qmp", RUNTIME / "boot-1.pid")
    print(f"boot 1 ok: created, recovered, self-check accepted, seed {fingerprint_one}")

    second = boot(2, secrets.token_hex(32))
    require("M0_TEST_COMPLETE:" in second, "boot 2 failed")
    require("m0_created=ok" not in second, "boot 2 created new state; recovery broken")
    require("release_self_check=accept" in second, "boot 2 self-check not accepted")
    fingerprint_two = fingerprint(second)
    require(fingerprint_one == fingerprint_two, "seed changed across boots")
    stop_vm(RUNTIME / "boot-2.qmp", RUNTIME / "boot-2.pid")
    print(f"boot 2 ok: recovery only, same seed, self-check accepted")

    print(f"REBOOT TEST PASSED: seed {fingerprint_one} persisted across two boots")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"REBOOT TEST FAILED: {error}")
        sys.exit(1)
