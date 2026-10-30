#!/usr/bin/env python3
"""Apply the reviewed SDK 1.1.11 initializer safety fix before building it."""
import argparse
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("source", type=Path)
args = parser.parse_args()
revision = subprocess.check_output(["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip()
if revision != "c0990e174fc75b2e52acd15882c62e69a3022581":
    raise SystemExit("Unsupported TrustTunnel SDK revision")
base = args.source / "platform/apple/VpnClient"
changes = {
    "VpnClient.mm": ("    _network_monitor->stop();\n    _network_monitor = nullptr;", "    if (_network_monitor) {\n        _network_monitor->stop();\n        _network_monitor = nullptr;\n    }"),
    "VpnClient.h": ("- (instancetype)initWithConfig:", "- (nullable instancetype)initWithConfig:"),
}
for name, (old, new) in changes.items():
    path = base / name
    source = path.read_text()
    if new in source:
        continue
    if source.count(old) != 1:
        raise SystemExit("Unexpected SDK source; review required")
    path.write_text(source.replace(old, new))
print("SDK initializer guard and nullable contract prepared")
