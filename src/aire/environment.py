"""Discover optional analysis tools without changing the user's shell."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path


def find_swift_demangler() -> str | None:
    """Find Swift in PATH or in the active Xcode toolchain on macOS."""
    configured = os.environ.get("GHIDRA_SWIFT_DEMANGLER")
    if configured:
        path = Path(configured).expanduser()
        return str(path.resolve()) if path.is_file() and os.access(path, os.X_OK) else None
    direct = shutil.which("swift-demangle")
    if direct:
        return direct
    if platform.system() != "Darwin":
        return None
    xcrun = shutil.which("xcrun")
    if not xcrun:
        return None
    try:
        result = subprocess.run(
            [xcrun, "--find", "swift-demangle"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        candidate = result.stdout.strip()
        if result.returncode == 0 and candidate and "\n" not in candidate:
            path = Path(candidate)
            if path.is_absolute() and path.is_file() and os.access(path, os.X_OK):
                return str(path)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def ghidra_environment() -> dict[str, str]:
    """Pass the discovered tool to Ghidra without altering the parent environment."""
    env = os.environ.copy()
    if not env.get("GHIDRA_SWIFT_DEMANGLER"):
        demangler = find_swift_demangler()
        if demangler:
            env["GHIDRA_SWIFT_DEMANGLER"] = demangler
    return env
