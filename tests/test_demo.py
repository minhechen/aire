"""Opt-in integration coverage against the installed Apple compiler/SDK."""

import json
import os
import platform
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from aire.platforms.ios.importer import inspect_ipa


@pytest.mark.integration
@pytest.mark.skipif(
    platform.system() != "Darwin" or os.environ.get("AIRE_TEST_XCODE") != "1",
    reason="Set AIRE_TEST_XCODE=1 on macOS with an iPhoneOS Xcode SDK",
)
@pytest.mark.parametrize("stripped", [False, True])
def test_real_ios_fixture_build_and_inventory(tmp_path, stripped):
    project = Path(__file__).resolve().parent.parent
    output = tmp_path / "Demo.ipa"
    command = [sys.executable, str(project / "examples/build_ios_demo.py"), "--output", str(output)]
    if stripped:
        command.append("--stripped")
    process = subprocess.run(command, check=True, text=True, capture_output=True, timeout=120)
    build = json.loads(process.stdout)
    assert build["unsigned"] is True
    assert Path(build["binary"]).read_bytes()[:4] == b"\xcf\xfa\xed\xfe"
    with zipfile.ZipFile(output) as archive:
        assert not any(name.endswith((".m", ".h")) for name in archive.namelist())
        assert not any("CodeSignature" in name for name in archive.namelist())
    result = inspect_ipa(output, tmp_path / "extracted")
    assert result.bundle_id == "org.aire.demo"
    assert len(result.images) == 1
    assert result.images[0].architecture == "arm64"
    assert result.images[0].status == "ready"
    names = {entity.name for entity in result.entities}
    assert "aire.favorites.v1" in names
    assert "https://api.aire-demo.invalid/v1/auth/code" in names
    assert "saveFavorite:" in names
    assert "PreviewStore" in names
    assert any(entity.kind == "resource" and "收藏" in entity.value for entity in result.entities)
    if not stripped:
        assert "-[FavoriteStore saveFavorite:]" in names
        assert "-[PreviewStore saveFavorite:]" in names
