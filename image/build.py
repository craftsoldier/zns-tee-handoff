#!/usr/bin/env python3
"""Custom minimal M0 initramfs builder. No VM launches or hardware requests."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fetch(pin, cache, archive):
    dest = cache / Path(pin["path"]).name
    if not dest.exists():
        with urllib.request.urlopen(archive + pin["path"], timeout=180) as src:
            with dest.open("xb") as out:
                shutil.copyfileobj(src, out)
    if digest(dest) != pin["sha256"]:
        raise RuntimeError(f"package hash mismatch: {dest.name}")
    return dest


def extract(pin, dest, cache, archive):
    subprocess.run(["dpkg-deb", "-x", str(fetch(pin, cache, archive)), str(dest)], check=True)


def entry(ino, name, mode, data):
    name = name.encode() + b"\0"
    values = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0)
    result = b"070701" + "".join(f"{v:08x}" for v in values).encode() + name
    result += b"\0" * (-len(result) % 4)
    result += data + b"\0" * (-len(data) % 4)
    return result


def pack(stage):
    chunks = [entry(1, ".", stat.S_IFDIR | 0o755, b"")]
    paths = sorted(stage.rglob("*"), key=lambda p: p.relative_to(stage).as_posix())
    for ino, path in enumerate(paths, 2):
        name = path.relative_to(stage).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            data, mode = os.readlink(path).encode(), stat.S_IFLNK | 0o777
        elif stat.S_ISDIR(mode):
            data, mode = b"", stat.S_IFDIR | 0o755
        elif stat.S_ISREG(mode):
            data, mode = path.read_bytes(), stat.S_IFREG | (0o755 if mode & 0o111 else 0o644)
        else:
            raise RuntimeError(f"unsupported guest entry: {name}")
        chunks.append(entry(ino, name, mode, data))
    chunks.append(entry(len(paths) + 2, "TRAILER!!!", 0, b""))
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, filename="", mode="wb", mtime=0, compresslevel=9) as out:
        out.write(b"".join(chunks))
    return stream.getvalue()


def install_member(pin, destination, work, cache, archive):
    extract(pin, work, cache, archive)
    source = work / pin["member"]
    if digest(source) != pin["member_sha256"]:
        raise RuntimeError(f"boot artifact hash mismatch: {source}")
    shutil.copyfile(source, destination)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--release-tag", default="", help="tag to bake into the guest release self-check")
    args = parser.parse_args()
    release_tag = args.release_tag.strip()
    if release_tag and (
        not release_tag.startswith("m0-v") or "/" in release_tag or any(c.isspace() for c in release_tag)
    ):
        raise RuntimeError("invalid release tag")
    commit = run("git", "rev-parse", "HEAD", cwd=ROOT)
    if commit != args.commit or run("git", "status", "--porcelain", "--untracked-files=no", cwd=ROOT):
        raise RuntimeError("build must use the exact expected commit with no tracked modifications")
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise RuntimeError("invalid source commit")
    pins = json.loads((ROOT / "image/pins.json").read_text())
    if not run("rustc", "--version").startswith(f"rustc {pins['rust']} "):
        raise RuntimeError("Rust compiler does not match image/pins.json")
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("measurement lock requires Python 3.12")
    output = args.output.resolve()
    # Never remove an existing output or staging directory.
    output.mkdir(parents=True, exist_ok=False)
    work = output.parent / (output.name + "-work")
    work.mkdir(exist_ok=False)
    cache = work / "downloads"
    cache.mkdir()
    stage = work / "stage"
    stage.mkdir()
    archive = pins["archive"]
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(work / "cargo-target")
    env["CARGO_INCREMENTAL"] = "0"
    env["SOURCE_DATE_EPOCH"] = "0"
    env["RELEASE_TAG"] = release_tag
    env["RUSTFLAGS"] = f"--remap-path-prefix={ROOT}=/src --remap-path-prefix={work}=/build"
    # Prevent panic/source strings from depending on cargo registry location.
    cargo_home = Path(env.get("CARGO_HOME", str(Path.home() / ".cargo"))).resolve()
    env["RUSTFLAGS"] += f" --remap-path-prefix={cargo_home}=/cargo"
    subprocess.run(["cargo", "build", "--locked", "--release"], cwd=ROOT, env=env, check=True)
    binary = work / "cargo-target/release/zns-tee-handoff"
    shutil.copyfile(binary, output / "zns-tee-handoff")
    for pin in pins["guest_packages"]:
        extract(pin, stage, cache, archive)
    # Ubuntu uses merged /usr. Ensure guest paths resolve within the initramfs.
    for name, target in (("bin", "usr/bin"), ("sbin", "usr/sbin"), ("lib", "usr/lib"), ("lib64", "usr/lib64")):
        path = stage / name
        if not path.exists() and not path.is_symlink():
            path.symlink_to(target)
    busyboxes = [p for p in stage.rglob("busybox") if p.is_file() and not p.is_symlink()]
    if len(busyboxes) != 1:
        raise RuntimeError("guest package must contain exactly one BusyBox binary")
    usrbin = stage / "usr/bin"
    usrbin.mkdir(parents=True, exist_ok=True)
    busybox = usrbin / "busybox"
    if busybox != busyboxes[0]:
        busybox.symlink_to(os.path.relpath(busyboxes[0], usrbin))
    (usrbin / "sh").symlink_to("busybox")
    # kmod dispatches legacy module commands by argv[0], not a subcommand.
    (usrbin / "insmod").symlink_to("kmod")
    localbin = stage / "usr/local/bin"
    localbin.mkdir(parents=True)
    shutil.copyfile(binary, localbin / "zns-tee-handoff")
    (localbin / "zns-tee-handoff").chmod(0o755)
    shutil.copyfile(ROOT / "image/init", stage / "init")
    (stage / "init").chmod(0o755)
    for name in ("proc", "sys", "dev", "run", "modules", "etc"):
        (stage / name).mkdir(exist_ok=True)
    install_member(pins["kernel"], output / "vmlinuz", work / "kernel", cache, archive)
    install_member(pins["ovmf"], output / "OVMF.amdsev.fd", work / "ovmf", cache, archive)
    modules = work / "kernel-modules"
    extract(pins["modules"], modules, cache, archive)
    base = modules / "usr/lib/modules" / pins["kernel_version"] / "kernel/drivers/virt/coco"
    for relative, name in (("guest/tsm_report.ko.zst", "tsm_report.ko"), ("sev-guest/sev-guest.ko.zst", "sev-guest.ko"), ("net/virtio_net.ko.zst", "virtio_net.ko")):
        source = base / relative
        compressed = True
        if not source.exists():
            source = base / relative.removesuffix(".zst")
            compressed = False
        with (stage / "modules" / name).open("xb") as target:
            subprocess.run(
                ["zstd", "-dc", str(source)] if compressed else ["cat", str(source)],
                stdout=target, check=True,
            )
    # Check the executable loader and direct library requirements against the guest payload.
    for executable in (localbin / "zns-tee-handoff", busyboxes[0], usrbin / "kmod"):
        dynamic = run("readelf", "-d", str(executable))
        import re
        for soname in re.findall(r"Shared library: \[(.*?)\]", dynamic):
            if not any(p.is_file() for p in stage.rglob(soname)):
                raise RuntimeError(f"missing guest library: {soname}")
    loader = stage / "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
    if not loader.is_file():
        raise RuntimeError("guest dynamic loader missing")
    loaderlink = stage / "usr/lib64/ld-linux-x86-64.so.2"
    if not loaderlink.exists():
        loaderlink.parent.mkdir(exist_ok=True)
        loaderlink.symlink_to("../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
    (output / "m0-initrd.img").write_bytes(pack(stage))
    profile = json.loads((ROOT / "image/launch-profile.json").read_text())
    (output / "launch-profile.json").write_text(json.dumps(profile, indent=2) + "\n")
    measurement_tool = ROOT / ".measure-venv/bin/sev-snp-measure"
    measurement = run(str(measurement_tool), "--mode", "snp", "--vmm-type", profile["vmm_type"],
        "--vcpus", str(profile["vcpus"]), "--vcpu-family", str(profile["cpu_family"]),
        "--vcpu-model", str(profile["cpu_model"]), "--vcpu-stepping", str(profile["cpu_stepping"]),
        "--guest-features", profile["guest_features"], "--ovmf", str(output / profile["ovmf"]),
        "--kernel", str(output / profile["kernel"]), "--initrd", str(output / profile["initrd"]),
        "--append", profile["cmdline"])
    if len(measurement) != 96 or any(c not in "0123456789abcdef" for c in measurement):
        raise RuntimeError("invalid expected SNP measurement output")
    (output / "snp-measurement.txt").write_text(measurement + "\n")
    print(f"Built source {commit}; expected SNP measurement {measurement}")


if __name__ == "__main__":
    main()
