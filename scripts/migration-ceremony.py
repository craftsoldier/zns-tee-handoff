#!/usr/bin/env python3
"""M0 -> M1 custody migration ceremony.

Run as root on the isolated SNP test host. The relay (this script, run by the
untrusted host operator) only moves text between guest consoles and GitHub
releases. Every security check happens inside the guests. VMs are stopped
only via their own QMP sockets after a name check.

Console I/O is socket-native and full-duplex. QEMU's chardev logfiles are
documented best-effort (qemu_chr_write_log silently drops on transient write
errors) and were observed dropping bytes; they are never a data channel. The
emulated UART is flow-controlled (QEMU reads the socket only as fast as the
guest drains its FIFO), so a single plain sendall() is paced by the guest.

Usage, in order:
  migration-ceremony.py verify TAG_M0 TAG_M1
                                            verify both image releases
  migration-ceremony.py genesis TAG_M0      boot M0: fresh seed -> custody-v1
  migration-ceremony.py recover TAG_M0      boot M0: custody-v1 -> armed
  migration-ceremony.py announce TAG_M0 TAG_M1
                                            boot M1: announce (M1 stays running)
  migration-ceremony.py migration TAG_M0 TAG_M1
                                            trigger M0, relay wrap to M1,
                                            capture custody-v2, stop M0 and M1
  migration-ceremony.py verify-m1 TAG_M0 TAG_M1
                                            fresh M1 boot recovers custody-v2
"""
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

if len(sys.argv) < 3 or sys.argv[1] not in ("verify", "genesis", "recover", "announce", "migration", "verify-m1"):
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


def boot(name, stem, assets, console_socket, log):
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
        "-qmp", f"unix:{RUNTIME / (stem + '.qmp')},server=on,wait=off",
        "-pidfile", str(RUNTIME / (stem + ".pid")), "-daemonize", "-no-reboot")


class Console:
    """Full-duplex client for a QEMU socket chardev console.

    Reads are the only trustworthy copy of guest output; the emulated UART
    flow-controls writes (QEMU reads the socket only as fast as the guest
    drains its FIFO), so plain sendall() needs no artificial pacing.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(2)
        deadline = time.time() + 15
        while True:
            try:
                self.sock.connect(str(self.path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.time() > deadline:
                    raise
                time.sleep(0.2)
        self.text = ""

    def _pump(self):
        try:
            data = self.sock.recv(65536)
        except socket.timeout:
            return
        if not data:
            raise RuntimeError(f"console {self.path} closed by peer")
        self.text += data.decode("utf-8", "replace") \
            .replace("\r\n", "\n").replace("\r", "\n")

    def send(self, line):
        self.sock.sendall(line.encode())

    def wait_for(self, marker, timeout=180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if marker in self.text:
                return self.text
            self._pump()
        raise RuntimeError(f"timeout waiting for {marker!r} on {self.path}")

    def read_block(self, begin, end, timeout=180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            lines = self.text.splitlines()
            if begin in lines and end in lines:
                return "\n".join(lines[lines.index(begin):lines.index(end) + 1])
            self._pump()
        raise RuntimeError(f"timeout waiting for {begin!r}..{end!r} on {self.path}")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def last_value(text, prefix):
    values = [line.split("=", 1)[1] for line in text.splitlines()
              if line.startswith(prefix)]
    require(values, f"no {prefix} line in console output")
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
    print("[genesis:1] checking lineage is clean (custody-v1 must not exist)")
    try:
        fetch_release("custody-v1")
        raise RuntimeError("custody-v1 already exists; delete it to start a fresh lineage")
    except urllib.error.HTTPError as error:
        require(error.code == 404, f"unexpected api status {error.code}")
    print("[genesis:2] fetching image assets")
    release = fetch_release(TAG_M0)
    download_asset(release, "m0-initrd.img", ASSETS_M0)
    download_asset(release, "vmlinuz", ASSETS_M0)
    download_asset(release, "OVMF.amdsev.fd", ASSETS_M0)
    print("[genesis:3] booting M0 (disk-less, console socket)")
    boot(NAME_M0, NAME_M0, ASSETS_M0, RUNTIME / "m0.console", RUNTIME / "m0.log")
    console = Console(RUNTIME / "m0.console")
    text = console.wait_for("m0_state_created=ok")
    print("[genesis:4] genesis marker on console stream")
    require("release_self_check=accept" in text, "self-check not accepted")
    block = console.read_block("GENESIS_STATE_BLOB_BEGIN", "GENESIS_STATE_BLOB_END", 10)
    hex_lines = block.splitlines()[1:-1]
    print(f"[genesis:5] blob block: {len(hex_lines)} line(s), "
          f"total {sum(len(l) for l in hex_lines)} hex chars")
    blob = bytes.fromhex("".join(hex_lines))
    print(f"[genesis:6] blob {len(blob)} bytes, magic {blob[:8]!r}")
    require(blob[:8] == b"LNST0001", "bad state magic")
    (RUNTIME / "state").write_bytes(blob)
    seed = last_value(text, "dummy_seed_sha256=")
    console.close()
    print(f"genesis ok: seed {seed}; M0 stays RUNNING (handoff armed)")
    print("RELAY NOW (authenticated machine):")
    print(f"  scp {RUNTIME}/state .")
    print(f"  gh release create custody-v1 --repo {REPO} --prerelease "
          f"--title 'custody state v1' --notes 'seed {seed}' state")
    print(f"then run: migration-ceremony.py announce {TAG_M0} {TAG_M1}")


def phase_recover():
    print("[recover:1] fetching image assets")
    release = fetch_release(TAG_M0)
    download_asset(release, "m0-initrd.img", ASSETS_M0)
    download_asset(release, "vmlinuz", ASSETS_M0)
    download_asset(release, "OVMF.amdsev.fd", ASSETS_M0)
    print("[recover:2] booting M0 (recovery path: custody-v1 -> armed listener)")
    boot(NAME_M0, NAME_M0, ASSETS_M0, RUNTIME / "m0.console", RUNTIME / "m0.log")
    console = Console(RUNTIME / "m0.console")
    text = console.wait_for("m0_handoff_armed=ok")
    require("state_recovered=ok" in text, "custody state not recovered")
    seed = last_value(text, "dummy_seed_sha256=")
    console.close()
    print(f"recover ok: M0 resurrected from custody-v1; seed {seed}; armed")
    print(f"next: migration-ceremony.py migration {TAG_M0} {TAG_M1}")


def phase_announce():
    require(fetch_release("custody-v1").get("tag_name") == "custody-v1",
            "custody-v1 must exist before the successor announces")
    release = fetch_release(TAG_M1)
    download_asset(release, "m0-initrd.img", ASSETS_M1)
    download_asset(release, "vmlinuz", ASSETS_M1)
    download_asset(release, "OVMF.amdsev.fd", ASSETS_M1)
    boot(NAME_M1, NAME_M1, ASSETS_M1, RUNTIME / "m1.console", RUNTIME / "m1.log")
    console = Console(RUNTIME / "m1.console")
    text = console.wait_for("ANNOUNCE_END")
    require("m1_announced=ok" in text, "M1 did not announce")
    announce = console.read_block("ANNOUNCE_BEGIN", "ANNOUNCE_END", 10)
    (RUNTIME / "announcement.txt").write_text(announce + "\n")
    console.close()
    print("M1 announced and stays RUNNING (it holds the wrap key)")
    print("RELAY NOW (authenticated machine):")
    print(f"  scp {RUNTIME}/announcement.txt .")
    print(f"  gh release upload {TAG_M1} announcement.txt --repo {REPO}")
    print(f"then run: migration-ceremony.py migration {TAG_M0} {TAG_M1}")


def valid_hex(value):
    return len(value) % 2 == 0 and all(c in "0123456789abcdef" for c in value)


def phase_migration():
    require(fetch_release("custody-v1").get("tag_name") == "custody-v1",
            "custody-v1 must exist")
    release = fetch_release(TAG_M1)
    assets = {a["name"]: a for a in release["assets"]}
    require("announcement.txt" in assets,
            f"upload announcement.txt to {TAG_M1} first")
    console_m0 = Console(RUNTIME / "m0.console")
    console_m0.send("\n")
    console_m0.send(f"HANDOFF {TAG_M1}\n")
    try:
        wrap = console_m0.read_block("WRAP_BEGIN", "WRAP_END", 120)
    except RuntimeError:
        print("no wrap after 120s; one clean re-trigger")
        console_m0.send("\n")
        console_m0.send(f"HANDOFF {TAG_M1}\n")
        wrap = console_m0.read_block("WRAP_BEGIN", "WRAP_END", 120)
    for line in wrap.splitlines():
        for field in ("ephemeral_pubkey=", "blob="):
            if line.startswith(field):
                require(valid_hex(line[len(field):]),
                        f"relay-side check: wrap {field} is not valid hex")
    print("wrap captured from M0's console stream; relaying to M1")
    console_m0.close()
    console_m1 = Console(RUNTIME / "m1.console")
    console_m1.send("\n")
    console_m1.send(wrap + "\n")
    state_block = console_m1.read_block("CUSTODY_STATE_BLOB_BEGIN",
                                        "CUSTODY_STATE_BLOB_END", 180)
    console_m1.wait_for("m1_custody_taken=ok", 30)
    seed = last_value(console_m1.text, "dummy_seed_sha256=")
    console_m1.close()
    hex_lines = state_block.splitlines()[1:-1]
    blob = bytes.fromhex("".join(hex_lines))
    require(blob[:8] == b"LNST0001", "bad state magic")
    (RUNTIME / "state").write_bytes(blob)
    print(f"M1 re-sealed the seed: {seed}")
    print("RELAY NOW (authenticated machine):")
    print(f"  scp {RUNTIME}/state .")
    print(f"  gh release create custody-v2 --repo {REPO} --prerelease "
          f"--title 'custody state v2' --notes 'sealed by {TAG_M1}; "
          f"seed {seed}' state")
    qmp_stop(RUNTIME / f"{NAME_M0}.qmp", NAME_M0, RUNTIME / f"{NAME_M0}.pid")
    print("M0 stopped (name-checked); its release remains bootable forever")
    qmp_stop(RUNTIME / f"{NAME_M1}.qmp", NAME_M1, RUNTIME / f"{NAME_M1}.pid")
    print("M1 stopped (name-checked); custody now lives in the releases")


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
    boot(NAME_M1, "m1-verify", ASSETS_M1,
         RUNTIME / "m1-verify.console", RUNTIME / "m1-verify.log")
    console = Console(RUNTIME / "m1-verify.console")
    text = console.wait_for("state_recovered=ok")
    require("release_self_check=accept" in text, "self-check not accepted")
    actual = last_value(text, "dummy_seed_sha256=")
    console.close()
    qmp_stop(RUNTIME / "m1-verify.qmp", NAME_M1, RUNTIME / "m1-verify.pid")
    require(actual == expected, f"fingerprint mismatch: expected {expected}")
    print(f"MIGRATION VERIFIED: seed {actual} recovered by {TAG_M1}")


if __name__ == "__main__":
    try:
        require(os.geteuid() == 0, "run as root on the isolated SNP test host")
        RUNTIME.mkdir(parents=True, exist_ok=True)
        {"verify": phase_verify, "genesis": phase_genesis, "recover": phase_recover, "announce": phase_announce,
         "migration": phase_migration, "verify-m1": phase_verify_m1}[PHASE]()
    except Exception as error:
        import traceback
        print(f"MIGRATION {PHASE.upper()} FAILED: {error}")
        traceback.print_exc()
        sys.exit(1)
