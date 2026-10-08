#!/usr/bin/env python3
"""Run as root on the test host, with previously verified release assets.
Touches only the new /home/ubuntu/dh_tests/m0-v0.5.0 test directory.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import time

ROOT = Path('/home/ubuntu/dh_tests/m0-v0.5.0')
ASSETS = ROOT / 'assets'
RUNTIME = ROOT / 'runtime'
DISK = ROOT / 'reboot-state.img'
UUID = 'df050000-0000-4000-8000-000000000005'
NAME = 'dh-m0-v0.5.0'

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout

def qmp(path, expected_name, quit_vm=False):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect(str(path))
        stream = sock.makefile('rwb')
        json.loads(stream.readline())
        def command(name):
            stream.write((json.dumps({'execute': name}) + '\n').encode())
            stream.flush()
            while True:
                reply = json.loads(stream.readline())
                if 'error' in reply:
                    raise RuntimeError(reply)
                if 'return' in reply:
                    return reply['return']
        command('qmp_capabilities')
        assert command('query-name')['name'] == expected_name
        if quit_vm:
            command('quit')

def stop(path, name, pidfile):
    pid = int(pidfile.read_text())
    qmp(path, name, True)
    for _ in range(100):
        if not Path(f'/proc/{pid}').exists():
            return
        time.sleep(.1)
    raise RuntimeError('test VM did not exit')

def put_file(source, destination):
    run('debugfs', '-w', '-R', f'write {source} {destination}', str(DISK))

def boot(number, challenge):
    control = RUNTIME / f'challenge-{number}'
    control.write_text(challenge)
    if number > 1:
        run('debugfs', '-w', '-R', 'rm /boot-challenge', str(DISK))
    put_file(control, '/boot-challenge')
    log = RUNTIME / f'boot-{number}.log'
    qmp_path = RUNTIME / f'boot-{number}.qmp'
    pidfile = RUNTIME / f'boot-{number}.pid'
    run('nice', '-n', '10', 'qemu-system-x86_64', '-name', NAME,
        '-enable-kvm', '-machine', 'q35,confidential-guest-support=sev0,vmport=off',
        '-cpu', 'host', '-smp', '2', '-m', '4G', '-object',
        'sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,policy=0x30000',
        '-bios', str(ASSETS/'OVMF.amdsev.fd'), '-kernel', str(ASSETS/'vmlinuz'),
        '-initrd', str(ASSETS/'m0-initrd.img'), '-append', 'console=ttyS0 rdinit=/init panic=-1',
        '-drive', f'file={DISK},if=virtio,format=raw', '-nic', 'none', '-display', 'none',
        '-serial', f'file:{log}', '-monitor', 'none', '-qmp', f'unix:{qmp_path},server=on,wait=off',
        '-pidfile', str(pidfile), '-daemonize', '-no-reboot')
    for _ in range(180):
        content = log.read_text(errors='replace') if log.exists() else ''
        if 'M0_TEST_COMPLETE:' in content or 'M0_TEST_FAILED:' in content:
            break
        time.sleep(1)
    else:
        stop(qmp_path, NAME, pidfile)
        raise RuntimeError('guest timed out')
    stop(qmp_path, NAME, pidfile)
    return content

def fields(content):
    return dict(line.split('=', 1) for line in content.splitlines() if '=' in line and not line.startswith('['))

def verify(content, challenge, measurement, certs, snpguest):
    assert 'M0_TEST_COMPLETE:' in content and 'M0_TEST_FAILED:' not in content
    values = fields(content)
    raw = bytes.fromhex(values['recovery_report_hex'])
    assert raw[0x90:0xc0].hex() == measurement
    assert struct.unpack_from('<Q', raw, 8)[0] == 0x30000
    assert (struct.unpack_from('<I', raw, 0x48)[0] >> 2) & 7 == 0
    binding = b'zns-tee-handoff/dummy-recovery/v1' + bytes.fromhex(challenge)
    for name in ('capsule_sha256', 'chip_layer_sha256', 'dummy_seed_sha256'):
        binding += bytes.fromhex(values[name])
    assert raw[0x50:0x90] == hashlib.sha512(binding).digest()
    report = RUNTIME / f'report-{challenge[:16]}.bin'
    report.write_bytes(raw)
    run(str(snpguest), 'verify', 'attestation', str(certs), str(report), '-p', 'siena')
    return {key: values[key] for key in ('dummy_seed_sha256', 'capsule_sha256', 'chip_layer_sha256')}

def main():
    assert os.geteuid() == 0
    assert ASSETS.is_dir() and not DISK.exists() and not RUNTIME.exists(), 'refuse existing test state'
    manifest = json.loads((ASSETS/'release-manifest.json').read_text())
    for name, expected in manifest['artifacts'].items():
        assert Path(name).name == name
        assert hashlib.sha256((ASSETS/name).read_bytes()).hexdigest() == expected, name
    assert manifest['launch']['memory_mib'] == 4096
    assert manifest['launch']['cmdline'] == 'console=ttyS0 rdinit=/init panic=-1'
    RUNTIME.mkdir(mode=0o700)
    # Explicitly stop only the older isolated test, after QMP name verification.
    old = Path('/home/ubuntu/dh_tests/m0-v0.4.0/runtime')
    if (old/'qmp.sock').exists():
        stop(old/'qmp.sock', 'dh-m0-v0.4.0', old/'qemu.pid')
    with DISK.open('xb') as file:
        file.truncate(256 * 1024 * 1024)
    run('mkfs.ext4', '-F', '-U', UUID, '-L', 'DH_REBOOT_TEST', str(DISK))
    flag = RUNTIME/'init-flag'
    flag.write_text('Dummy secrets only. First creation authorized.\n')
    put_file(flag, '/INIT_ALLOWED')
    first_challenge, second_challenge = secrets.token_hex(32), secrets.token_hex(32)
    first = boot(1, first_challenge)
    second = boot(2, second_challenge)
    assert 'm0_created=ok' in first and 'm0_created=ok' not in second
    certs = old/'certs'
    pinned_ark = hashlib.sha256(subprocess.check_output(['openssl','x509','-in',str(certs/'ark.pem'),'-outform','DER'])).hexdigest()
    assert pinned_ark == '4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1'
    snpguest = Path('/home/ubuntu/snpguest/target/release/snpguest')
    run(str(snpguest), 'verify', 'certs', str(certs))
    # The existing VCEK is suitable only if the same chip and TCB signed both reports.
    measurement = manifest['expected_snp_measurement']
    baseline = verify(first, first_challenge, measurement, certs, snpguest)
    recovered = verify(second, second_challenge, measurement, certs, snpguest)
    assert baseline == recovered
    original = RUNTIME/'original.capsule'
    run('debugfs', '-R', f'dump /m0/seed.capsule {original}', str(DISK))
    damaged = bytearray(original.read_bytes())
    damaged[-1] ^= 1
    tampered = RUNTIME/'tampered.capsule'
    tampered.write_bytes(damaged)
    run('debugfs', '-w', '-R', 'rm /m0/seed.capsule', str(DISK))
    put_file(tampered, '/m0/seed.capsule')
    third = boot(3, secrets.token_hex(32))
    assert 'M0_TEST_FAILED: recover' in third and 'm0_created=ok' not in third
    run('debugfs', '-w', '-R', 'rm /m0/seed.capsule', str(DISK))
    put_file(original, '/m0/seed.capsule')
    result = dict(baseline, release='m0-v0.5.0', measurement=measurement,
                  fresh_attestation_verified=True, separate_boot_recovery=True,
                  corrupted_capsule_rejected_without_regeneration=True,
                  production_guest_running=Path('/proc/253532').exists())
    (RUNTIME/'verification.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
