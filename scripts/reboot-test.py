#!/usr/bin/env python3
"""M0 stateless boot test. Run as root on the isolated SNP test host.

Usage:
  reboot-test.py genesis TAG   custody release must NOT exist yet; boots a
                               disk-less guest, expects genesis, saves the
                               state blob, prints the relay commands.
  reboot-test.py recovery TAG  custody release must exist; boots a fresh
                               disk-less guest, expects recovery-only with
                               the seed fingerprint and self-check accept.

Both boots verify all release asset digests against the GitHub API first, and
stop their VM only through its own QMP socket after the reported name matches
dh-<TAG>. No state disk exists anywhere in this test.
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

if len(sys.argv) != 3 or sys.argv[1] not in ("genesis", "recovery"):
    raise SystemExit(__doc__)
PHASE, TAG = sys.argv[1], sys.argv[2]
assert TAG.startswith("m0-v"), "tag must look like m0-vX.Y.Z"

REPO = "craftsoldier/zns-tee-handoff"
API = f"https://api.github.com/repos/{REPO}/releases/tags"
CUSTODY_STATE = "custody-v1"
ROOT = Path("/home/ubuntu/dh_tests") / TAG
ASSETS, RUNTIME = ROOT / "assets", ROOT / "runtime"
NAME = f"dh-{TAG}"
REQUIRED_ASSETS = ("m0-initrd.img", "vmlinuz", "OVMF.amdsev.fd")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def api_json(url, accept):
    request = urllib.request.Request(url, headers={
        "User-Agent": "zns-custody-reboot-test", "Accept": accept,
    })
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read())


def fetch_release(tag):
    return api_json(f"{API}/{tag}", "application/vnd.github+json")


def download_assets(release, names):
    ASSETS.mkdir(parents=True, exist_ok=True)
    for asset in release["assets"]:
        if asset["name"] not in names:
            continue
        digest = asset["digest"]
        require(digest.startswith("sha256:"), f"no digest for {asset['name']}")
        target = ASSETS / asset["name"]
        request = urllib.request.Request(asset["url"], headers={
            "User-Agent": "zns-custody-reboot-test",
            "Accept": "application/octet-stream",
        })
        with urllib.request.urlopen(request, timeout=300) as response:
            target.write_bytes(response.read())
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        require(actual == digest[7:], f"digest mismatch: {asset['name']}")
        print(f"verified {asset['name']}")


def stop_vm(qmp_path, pidfile):
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


def boot(number):
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


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def fingerprint(log):
    values = [line.split("=", 1)[1] for line in log.splitlines()
              if line.startswith("dummy_seed_sha256=")]
    require(len(values) >= 1, "no seed fingerprint in log")
    return values[-1]


def main():
    require(os.geteuid() == 0, "run as root on the isolated SNP test host")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    image_release = fetch_release(TAG)
    require(image_release["tag_name"] == TAG, "api returned a different tag")
    download_assets(image_release, REQUIRED_ASSETS)

    if PHASE == "genesis":
        try:
            fetch_release(CUSTODY_STATE)
            raise RuntimeError(f"{CUSTODY_STATE} already exists; a seed is created once")
        except urllib.error.HTTPError as error:
            require(error.code == 404, f"unexpected api status {error.code}")
        log = boot(1)
        require("M0_TEST_COMPLETE:" in log, "genesis boot failed")
        require("m0_state_created=ok" in log, "genesis did not create state")
        require("release_self_check=accept" in log, "self-check not accepted")
        lines = log.splitlines()
        begin = lines.index("GENESIS_STATE_BLOB_BEGIN")
        end = lines.index("GENESIS_STATE_BLOB_END")
        blob = bytes.fromhex("".join(lines[begin + 1:end]))
        require(len(blob) == 168, "unexpected state blob length")
        (RUNTIME / "state").write_bytes(blob)
        stop_vm(RUNTIME / "boot-1.qmp", RUNTIME / "boot-1.pid")
        print(f"genesis ok: seed {fingerprint(log)}")
        print("RELAY NOW (authenticated machine):")
        print(f"  scp {ROOT}/runtime/state . && gh release create {CUSTODY_STATE} "
              f"--repo {REPO} --prerelease --title 'custody state v1' "
              f"--notes 'seed {fingerprint(log)}' state")
    else:
        custody = fetch_release(CUSTODY_STATE)
        assets = {a["name"]: a for a in custody["assets"]}
        require("state" in assets, "custody release has no state asset")
        request = urllib.request.Request(assets["state"]["url"], headers={
            "User-Agent": "zns-custody-reboot-test",
            "Accept": "application/octet-stream",
        })
        with urllib.request.urlopen(request, timeout=120) as response:
            blob = response.read()
        digest = assets["state"]["digest"]
        require(digest.startswith("sha256:"), "custody asset digest missing")
        require(hashlib.sha256(blob).hexdigest() == digest[7:],
                "custody state digest mismatch")
        expected = blob[8:40].hex()
        log = boot(2)
        require("M0_TEST_COMPLETE:" in log, "recovery boot failed")
        require("m0_state_created=ok" not in log, "recovery boot created new state")
        require("release_self_check=accept" in log, "self-check not accepted")
        require(fingerprint(log) == expected, "seed changed across boots")
        stop_vm(RUNTIME / "boot-2.qmp", RUNTIME / "boot-2.pid")
        print(f"recovery ok: custody seed {expected} recovered, self-check accepted")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"{PHASE.upper()} TEST FAILED: {error}")
        sys.exit(1)
