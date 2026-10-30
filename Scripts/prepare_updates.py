#!/usr/bin/env python3
"""Fetch the pinned official Sparkle tools. Never generates/exports private keys."""
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]

def prepare():
    lock = json.loads((ROOT / 'dependency-lock.json').read_text())
    version = lock['sparkleVersion']
    destination = ROOT / '.build-deps' / ('sparkle-' + version)
    archive = ROOT / '.build-deps' / ('Sparkle-' + version + '.tar.xz')
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        temporary = archive.with_suffix('.download')
        with urllib.request.urlopen('https://github.com/sparkle-project/Sparkle/releases/download/' + version + '/' + archive.name, timeout=60) as response:
            with temporary.open('wb') as output:
                shutil.copyfileobj(response, output)
        temporary.replace(archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != lock['sparkleToolsSHA256']:
        raise SystemExit('Sparkle archive checksum mismatch')
    if not destination.exists():
        destination.mkdir()
        try:
            with tarfile.open(archive) as source:
                source.extractall(destination, filter='data')
        except BaseException:
            shutil.rmtree(destination)
            raise
    return destination

if __name__ == '__main__':
    print(prepare())
