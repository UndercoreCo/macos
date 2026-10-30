#!/usr/bin/env python3
"""Reproducible local Apple Silicon build. Does not install or activate a VPN."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tarfile
import urllib.request
from prepare_updates import prepare as prepare_updates

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--configuration', choices=['Debug', 'Release'], default='Release')
parser.add_argument('--team', help='Existing Apple Developer team for a signed build')
parser.add_argument('--provision', action='store_true', help='Allow Xcode to manage development profiles')
parser.add_argument('--register-device', action='store_true', help='Allow registering this Mac for development provisioning')
parser.add_argument('--test', action='store_true')
parser.add_argument('--build-number', type=int, help='Strictly increasing Sparkle/extension build number')
parser.add_argument('--enable-updates', action='store_true', help='Enable the published signed test feed')
parser.add_argument('--developer-id', help='Developer ID Application identity or SHA-1 for standalone distribution')
parser.add_argument('--archive', type=Path, help='Create an xcarchive at this new path instead of a regular build')
parser.add_argument('--backend', choices=['standalone', 'network-extension'], default='standalone')
parser.add_argument('--trusttunnel', action='store_true', help='Include the experimental, locally prepared TrustTunnel SDK')
args = parser.parse_args()
if args.trusttunnel and args.backend != 'network-extension':
    parser.error('--trusttunnel requires --backend network-extension')
if args.trusttunnel and not (ROOT / '.build-deps/TrustTunnel/VpnClientFramework.framework').is_dir():
    parser.error('Prepare the TrustTunnel SDK first; see docs/internal/macos/trusttunnel.md')
if args.trusttunnel and args.enable_updates:
    parser.error('Experimental TrustTunnel builds cannot enable the published update feed')
if args.build_number is not None and not 4 <= args.build_number <= 2147483647:
    parser.error('--build-number must be at least 4')
if args.developer_id and (args.backend != 'standalone' or not args.team or args.configuration != 'Release'):
    parser.error('--developer-id requires --backend standalone, --team and Release')
if args.backend == 'standalone' and args.team and not args.developer_id:
    parser.error('Signed standalone builds require --developer-id')
if args.archive:
    args.archive = args.archive.expanduser().resolve()
    if args.archive.suffix != '.xcarchive' or args.archive.exists():
        parser.error('--archive must name a new .xcarchive path')
    if args.configuration != 'Release':
        parser.error('Archives require Release')
if args.register_device and (not args.provision or args.backend != 'network-extension'):
    parser.error('--register-device requires --provision and --backend network-extension')
if args.provision and not args.team:
    parser.error('--provision requires --team')
if platform.machine() != 'arm64':
    raise SystemExit('This first prototype targets Apple Silicon. Intel support has not been verified.')
lock = json.loads((ROOT / 'dependency-lock.json').read_text())
deps = ROOT / '.build-deps'
deps.mkdir(exist_ok=True)
go = deps / 'go/bin/go'
if not go.exists():
    archive = deps / 'go-toolchain.tgz'
    with urllib.request.urlopen('https://go.dev/dl/go' + lock['goVersion'] + '.darwin-arm64.tar.gz') as response:
        with archive.open('wb') as output:
            shutil.copyfileobj(response, output)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['goDarwinArm64SHA256']:
        raise SystemExit('Go toolchain checksum mismatch')
    with tarfile.open(archive) as tar:
        tar.extractall(deps, filter='data')
    archive.unlink()
version = subprocess.check_output([str(go), 'version'], text=True)
if 'go' + lock['goVersion'] + ' ' not in version:
    raise SystemExit('Unexpected local Go version')
subprocess.run(['python3', str(ROOT / 'Scripts/prepare.py')], check=True)
env = {**os.environ, 'PATH':str(go.parent) + os.pathsep + os.environ['PATH'],
       'GOTOOLCHAIN':'local', 'GOPATH':str(deps / 'go-cache'), 'GOCACHE':str(deps / 'go-build-cache'),
       'GOFLAGS':'-mod=readonly'}
engine = deps / 'engine'
subprocess.run([str(go), 'mod', 'download'], cwd=engine, env=env, check=True)
subprocess.run([str(go), 'mod', 'verify'], cwd=engine, env=env, check=True)
if args.backend == 'network-extension':
    subprocess.run(['make', 'ARCHS=arm64', 'DESTDIR='+str(deps / 'lib'),
                    'DEPLOYMENT_TARGET_CLANG_FLAG_NAME=mmacosx-version-min',
                    'DEPLOYMENT_TARGET_CLANG_ENV_NAME=MACOSX_DEPLOYMENT_TARGET',
                    'MACOSX_DEPLOYMENT_TARGET=14.0'], cwd=engine, env=env, check=True)
else:
    output = ROOT / '.build/standalone'
    output.mkdir(parents=True, exist_ok=True)
    helper_env = {**env, 'CGO_ENABLED':'1', 'CGO_CFLAGS':'-mmacosx-version-min=14.0', 'CGO_LDFLAGS':'-mmacosx-version-min=14.0'}
    subprocess.run([str(go), 'mod', 'verify'], cwd=ROOT / 'Helper', env=helper_env, check=True)
    if args.test:
        subprocess.run([str(go), 'test', '-race', '-count=1', './...'], cwd=ROOT / 'Helper', env=helper_env, check=True)
    subprocess.run([str(go), 'build', '-trimpath', '-ldflags=-s -w', '-o', str(output / 'undercore-helper'), '.'], cwd=ROOT / 'Helper', env=helper_env, check=True)
    helper_signing = ['/usr/bin/codesign', '--force', '--sign', args.developer_id or '-']
    if args.developer_id:
        helper_signing += ['--options', 'runtime', '--timestamp', '--identifier', 'ru.undercore.macos.helper']
    subprocess.run([*helper_signing, str(output / 'undercore-helper')], check=True)
# Include license texts for shipped dependencies, not only the top-level adapter.
sparkle_tools = prepare_updates()
notices = ['Sparkle\n' + (sparkle_tools / 'LICENSE').read_text(), 'AmneziaWG Apple adapter\n' + (deps / 'amneziawg-apple/COPYING').read_text(),
           'Go runtime\n' + (deps / 'go/LICENSE').read_text()]
for path in sorted((deps / 'go-cache/pkg/mod').glob('**/LICENSE')):
    if '/cache/' not in str(path) and path.is_file():
        notices.append(str(path.parent.relative_to(deps / 'go-cache/pkg/mod')) + '\n' + path.read_text())
if args.trusttunnel:
    notices.append((deps / 'TrustTunnel/ThirdPartyNotices.txt').read_text())
(ROOT / 'Config/ThirdPartyNotices.txt').write_text('\n\n--------------------\n\n'.join(notices))
subprocess.run(['python3', str(ROOT / 'Scripts/project.py'), '--backend', args.backend] + (['--trusttunnel'] if args.trusttunnel else []), check=True)
if args.test:
    subprocess.run(['swift', 'test', '--package-path', str(ROOT / 'Core')], check=True)
    shutil.copyfile(ROOT / 'Engine/loopback_test.go', engine / 'loopback_test.go')
    subprocess.run([str(go), 'test', '-count=1', '-timeout=30s', '-run', '^TestAWG31Loopback$', '.'], cwd=engine, env=env, check=True)
build_directory = ROOT / 'DerivedData' / (args.backend + ('-developer-id' if args.developer_id else ''))
command = ['xcodebuild', '-project', str(ROOT / 'Undercore.xcodeproj'), '-scheme', 'Undercore',
           '-configuration', args.configuration, '-destination', 'platform=macOS,arch=arm64',
           '-derivedDataPath', str(build_directory), 'ARCHS=arm64', '-clonedSourcePackagesDirPath', str(deps / 'SwiftPackages'), '-disableAutomaticPackageResolution']
if args.build_number is not None: command.append('CURRENT_PROJECT_VERSION=' + str(args.build_number))
if args.enable_updates: command.append('UNDERCORE_UPDATES_ENABLED=YES')
if args.backend == 'standalone':
    command += ['CODE_SIGNING_ALLOWED=YES', 'CODE_SIGN_IDENTITY=' + (args.developer_id or '-')]
    if args.developer_id:
        command += ['DEVELOPMENT_TEAM=' + args.team, 'OTHER_CODE_SIGN_FLAGS=--timestamp', 'CODE_SIGN_STYLE=Manual']
elif args.team:
    command.append('DEVELOPMENT_TEAM='+args.team)
    if args.provision: command.append('-allowProvisioningUpdates')
    if args.register_device: command.append('-allowProvisioningDeviceRegistration')
else:
    command.append('CODE_SIGNING_ALLOWED=NO')
if args.archive:
    command += ['-archivePath', str(args.archive), 'archive']
else:
    command.append('build')
subprocess.run(command, check=True)
if args.backend == 'network-extension':
    built_app = (args.archive / 'Products/Applications/Undercore.app' if args.archive
                 else build_directory / 'Build/Products' / args.configuration / 'Undercore.app')
    extension = built_app / 'Contents/Library/SystemExtensions/ru.undercore.macos.tunnel.systemextension'
    for bundle in [built_app, extension]:
        info = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())
        if not info.get('NSSystemExtensionUsageDescription', '').strip():
            raise SystemExit(f'Missing system extension usage description: {bundle.name}')
if args.team:
    app = (args.archive / 'Products/Applications/Undercore.app' if args.archive
           else build_directory / 'Build/Products' / args.configuration / 'Undercore.app')
    embedded = (app / 'Contents/Resources/undercore-helper' if args.backend == 'standalone'
                else app / 'Contents/Library/SystemExtensions/ru.undercore.macos.tunnel.systemextension')
    for signed_item in [embedded, app]:
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '--verbose=2', str(signed_item)], check=True)
    if args.backend == 'network-extension':
        entitlements = plistlib.loads(subprocess.check_output(
            ['/usr/bin/codesign', '-d', '--entitlements', ':-', str(embedded)], stderr=subprocess.DEVNULL))
        info = plistlib.loads((embedded / 'Contents/Info.plist').read_bytes())
        service = info['NetworkExtension']['NEMachServiceName']
        groups = entitlements.get('com.apple.security.application-groups', [])
        if not any(service.startswith(group + '.') for group in groups):
            raise SystemExit('Tunnel Mach service must be prefixed by its signed app group')
print('Built:', args.archive or build_directory / 'Build/Products' / args.configuration / 'Undercore.app')
print('No app installed and no VPN started. Backend:', args.backend)
