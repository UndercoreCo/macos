#!/usr/bin/env python3
"""Build the pinned upstream macOS CLI without Apple NetworkExtension entitlements.

Does not install a daemon, request administrator rights, or change networking.
Requires the local Go toolchain prepared by Scripts/build.py.
"""
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
lock = json.loads((ROOT / 'dependency-lock.json').read_text())
deps = ROOT / '.build-deps'
go = deps / 'go/bin/go'
if platform.system() != 'Darwin' or platform.machine() != 'arm64':
    raise SystemExit('This experiment is currently verified only on Apple Silicon macOS.')
if not go.exists():
    raise SystemExit('Prepare the pinned toolchain with Scripts/build.py first.')
version = subprocess.check_output([str(go), 'version'], text=True)
if 'go' + lock['goVersion'] + ' ' not in version:
    raise SystemExit('Unexpected local Go version')
env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOFLAGS': '-mod=readonly',
       'GOPATH': str(deps / 'go-cache'), 'GOCACHE': str(deps / 'go-build-cache'),
       'CGO_ENABLED': '0', 'GOOS': 'darwin', 'GOARCH': 'arm64'}
module = json.loads(subprocess.check_output(
    [str(go), 'list', '-m', '-json', lock['awgModule']], cwd=ROOT / 'Engine', env=env, text=True))
if module.get('Version') != lock['awgVersion'] or module.get('Replace'):
    raise SystemExit('Unexpected AWG module version or local replacement')
subprocess.run([str(go), 'mod', 'verify'], cwd=ROOT / 'Engine', env=env, check=True)
output = ROOT / '.build/standalone'
output.mkdir(parents=True, exist_ok=True)
binary = output / 'amneziawg-go'
subprocess.run([str(go), 'build', '-trimpath', '-ldflags=-s -w', '-o', str(binary),
                lock['awgModule']], cwd=ROOT / 'Engine', env=env, check=True)
# Apple Silicon Mach-O still needs a local code signature. Ad-hoc uses no certificate,
# team, provisioning profile, paid account, or restricted entitlements.
subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(binary)], check=True)
subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(binary)], check=True)
subprocess.run([str(binary), '--version'], check=True)
subprocess.run([str(go), 'version', '-m', str(binary)], check=True)
print('Built standalone experiment:', binary)
print('Upstream --version is a legacy string; the embedded Go module version above is authoritative.')
print('No VPN started. A complete client still needs privileged lifecycle, routes, DNS and cleanup.')
