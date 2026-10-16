import subprocess

import pytest

from aire import environment


@pytest.fixture(autouse=True)
def no_configured_override(monkeypatch):
    monkeypatch.delenv("GHIDRA_SWIFT_DEMANGLER", raising=False)


def test_path_tool_wins_without_starting_xcrun(monkeypatch):
    monkeypatch.setattr(environment.shutil, "which", lambda name: "/tools/swift-demangle")
    monkeypatch.setattr(environment.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("xcrun should not run")))
    assert environment.find_swift_demangler() == "/tools/swift-demangle"


def test_xcode_tool_is_found_when_absent_from_path(tmp_path, monkeypatch):
    executable = tmp_path / "swift-demangle"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    monkeypatch.setattr(environment.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(environment.shutil, "which", lambda name: "/usr/bin/xcrun" if name == "xcrun" else None)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, str(executable) + "\n", "")

    monkeypatch.setattr(environment.subprocess, "run", run)
    assert environment.find_swift_demangler() == str(executable)
    assert calls == [["/usr/bin/xcrun", "--find", "swift-demangle"]]


def test_xcrun_failure_is_an_optional_tool_absence(monkeypatch):
    monkeypatch.setattr(environment.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(environment.shutil, "which", lambda name: "/usr/bin/xcrun" if name == "xcrun" else None)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("xcrun", 5)

    monkeypatch.setattr(environment.subprocess, "run", timeout)
    assert environment.find_swift_demangler() is None


def test_non_macos_without_swift_does_not_invoke_xcrun(monkeypatch):
    monkeypatch.setattr(environment.platform, "system", lambda: "Linux")
    monkeypatch.setattr(environment.shutil, "which", lambda name: None)
    assert environment.find_swift_demangler() is None


def test_worker_receives_tool_path_without_mutating_user_environment(tmp_path, monkeypatch):
    executable = tmp_path / "swift-demangle"
    executable.write_text("tool")
    executable.chmod(0o755)
    monkeypatch.setattr(environment.shutil, "which", lambda name: str(executable))
    child = environment.ghidra_environment()
    assert child["GHIDRA_SWIFT_DEMANGLER"] == str(executable)
    assert "GHIDRA_SWIFT_DEMANGLER" not in environment.os.environ


def test_explicit_ghidra_demangler_is_preserved(tmp_path, monkeypatch):
    executable = tmp_path / "custom-demangler"
    executable.write_text("tool")
    executable.chmod(0o755)
    monkeypatch.setenv("GHIDRA_SWIFT_DEMANGLER", str(executable))
    assert environment.find_swift_demangler() == str(executable)
    assert environment.ghidra_environment()["GHIDRA_SWIFT_DEMANGLER"] == str(executable)
