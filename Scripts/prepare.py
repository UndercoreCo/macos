#!/usr/bin/env python3
"""Prepare only the pinned AWG adapter and bridge; no upstream app, UI or Xray."""
from pathlib import Path
import json
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
lock = json.loads((ROOT / 'dependency-lock.json').read_text())
deps = ROOT / '.build-deps'
deps.mkdir(exist_ok=True)
source = deps / 'amneziawg-apple'
if not source.exists():
    subprocess.run(['git', 'clone', '--no-checkout', lock['appleRepository'], str(source)], check=True)
    subprocess.run(['git', '-C', str(source), 'checkout', '--detach', lock['appleRevision']], check=True)
revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
if revision != lock['appleRevision']:
    raise SystemExit('Wrong upstream revision; use the revision from dependency-lock.json')
if subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip():
    raise SystemExit('Upstream checkout contains local changes; refusing an unverified adapter')
package = deps / 'AWGKit'
package.mkdir(exist_ok=True)
for name in ['WireGuardKit', 'WireGuardKitC']:
    shutil.copytree(source / 'Sources' / name, package / 'Sources' / name, dirs_exist_ok=True)
bridge = package / 'Sources' / 'WireGuardKitGo'
bridge.mkdir(parents=True, exist_ok=True)
for name in ['wireguard.h', 'module.modulemap', 'dummy.c']:
    shutil.copyfile(source / 'Sources/WireGuardKitGo' / name, bridge / name)
parser = (source / 'Sources/Shared/Model/TunnelConfiguration+WgQuickConfig.swift').read_text()
# The upstream app keeps its parser internal; expose just its initializer to our wrapper.
parser = parser.replace('    convenience init(fromWgQuickConfig', '    public convenience init(fromWgQuickConfig')
(package / 'Sources/WireGuardKit/TunnelConfiguration+WgQuickConfig.swift').write_text(parser)
shutil.copyfile(source / 'Sources/Shared/Model/String+ArrayConversion.swift', package / 'Sources/WireGuardKit/String+ArrayConversion.swift')
models = package / 'Sources/WireGuardConfiguration'
models.mkdir(parents=True, exist_ok=True)
for path in (package / 'Sources/WireGuardKit').glob('*.swift'):
    if path.name not in {'WireGuardAdapter.swift', 'PacketTunnelSettingsGenerator.swift', 'DNSResolver.swift'}:
        shutil.copyfile(path, models / path.name)
(package / 'Package.swift').write_text('''// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "AWGKit", platforms: [.macOS(.v14)],
    products: [.library(name: "WireGuardKit", targets: ["WireGuardKit"]), .library(name: "WireGuardConfiguration", targets: ["WireGuardConfiguration"])],
    targets: [
        .target(name: "WireGuardConfiguration", dependencies: ["WireGuardKitC"]),
        .target(name: "WireGuardKit", dependencies: ["WireGuardKitC", "WireGuardKitGo"]),
        .target(name: "WireGuardKitC", publicHeadersPath: "."),
        .target(name: "WireGuardKitGo", publicHeadersPath: ".",
                linkerSettings: [.unsafeFlags(["-L", "''' + str(deps / 'lib') + '''"]), .linkedLibrary("wg-go"), .linkedLibrary("resolv")])
    ])
''')
shutil.copyfile(source / 'COPYING', package / 'LICENSE')
engine = deps / 'engine'
engine.mkdir(exist_ok=True)
for name in ['api-apple.go', 'Makefile', 'goruntime-boottime-over-monotonic.diff']:
    shutil.copyfile(source / 'Sources/WireGuardKitGo' / name, engine / name)
for name in ['go.mod', 'go.sum']:
    if (ROOT / 'Engine' / name).exists():
        shutil.copyfile(ROOT / 'Engine' / name, engine / name)
print('Prepared pinned AWG 3.1 adapter and Go bridge, without Xray')
