Undercore for macOS

Native client source snapshot, 2026-10-31. App/, Core/, Tunnel/, Engine/ and Helper/ contain application and connection code. Scripts/build.py and dependency-lock.json describe the pinned build. Start with: python3 Scripts/build.py --help

Requires macOS, Xcode and the build dependencies requested by Scripts/. Distribution signing, notarization and automatic-update private keys are not included. Third-party notices are in Config/. This publication does not build, sign or release an application update.
