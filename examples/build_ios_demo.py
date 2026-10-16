#!/usr/bin/env python3
"""Build a genuine unsigned arm64 iOS IPA for static-analysis evaluation.

Requires macOS and Xcode with an iPhoneOS SDK. No Python dependencies:

    python3 examples/build_ios_demo.py
    python3 examples/build_ios_demo.py --stripped
    python3 examples/build_ios_demo.py --output /tmp/aire-demo.ipa

The default outputs are .aire/demo/AireDemo.ipa and (with --stripped)
.aire/demo/AireDemo-stripped.ipa. The corresponding extracted app bundle is
retained beside the IPA. No app is launched, installed, signed, or uploaded.

The compiler invocation is printed for review. Builds are source-reproducible;
the installed SDK/compiler version can change output bytes. Stable archive
timestamps are used so ZIP packaging itself does not introduce timestamps.
"""

from __future__ import annotations

import argparse
import json
import platform
import shlex
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def build_demo(output: Path, *, stripped: bool = False) -> dict[str, str | bool]:
    if platform.system() != "Darwin":
        raise RuntimeError("Building the iOS demo requires macOS and Xcode")
    if shutil.which("xcrun") is None:
        raise RuntimeError("xcrun is unavailable; select an Xcode developer directory")
    source = Path(__file__).resolve().parent / "ios-demo"
    output = output.resolve()
    # Only generated files in this dedicated per-output directory are replaced.
    build_root = output.parent / f"{output.stem}-build"
    app = build_root / "Payload" / "AireDemo.app"
    app.mkdir(parents=True, exist_ok=True)
    binary = app / "AireDemo"
    sdk = subprocess.check_output(
        ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True
    ).strip()
    sources = sorted(source.glob("*.m"))
    command = [
        "xcrun",
        "--sdk",
        "iphoneos",
        "clang",
        "-target",
        "arm64-apple-ios15.0",
        "-isysroot",
        sdk,
        "-fobjc-arc",
        "-O1",
        "-g0",
        "-framework",
        "Foundation",
        "-framework",
        "UIKit",
        "-Wl,-no_adhoc_codesign",
        "-Wl,-no_uuid",
        *map(str, sources),
        "-o",
        str(binary),
    ]
    print(shlex.join(command), file=sys.stderr)
    subprocess.run(command, check=True)
    if stripped:
        subprocess.run(["xcrun", "strip", "-S", "-x", str(binary)], check=True)
    for resource in sorted(source.rglob("*")):
        if resource.is_file() and resource.suffix in {".plist", ".strings"}:
            target = app / resource.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(resource, target)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(app.rglob("*")):
            if not file.is_file():
                continue
            name = file.relative_to(build_root).as_posix()
            entry = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, file.read_bytes())
    return {
        "ipa": str(output),
        "binary": str(binary),
        "sdk": sdk,
        "architecture": "arm64",
        "unsigned": True,
        "stripped": stripped,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="IPA output path")
    parser.add_argument("--stripped", action="store_true", help="Remove local/debug symbols")
    args = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    name = "AireDemo-stripped.ipa" if args.stripped else "AireDemo.ipa"
    output = args.output or project / ".aire" / "demo" / name
    try:
        print(json.dumps(build_demo(output, stripped=args.stripped), indent=2))
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Demo build failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
