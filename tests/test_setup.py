import json
import os
import sys
import tomllib
from pathlib import Path

import pytest

from aire import setup


@pytest.fixture(autouse=True)
def bundled_skill(monkeypatch):
    files = {
        "SKILL.md": b"---\nname: aire-investigate\ndescription: Investigate an IPA.\n---\n",
        "agents/openai.yaml": b"interface:\n  display_name: aire\n",
    }
    monkeypatch.setattr(setup, "_bundled_skill", lambda: dict(files))
    for name in setup._ENV_ALLOWLIST:
        monkeypatch.delenv(name, raising=False)
    return files


def server_for(client, path):
    data = tomllib.loads(path.read_text()) if client == "codex" else json.loads(path.read_text())
    return data["mcp_servers" if client == "codex" else "mcpServers"]["aire"]


@pytest.mark.parametrize("client", ["codex", "claude-code"])
def test_preview_is_concrete_and_does_not_create_any_files(tmp_path, client):
    workspace = tmp_path / "private work"
    result = setup.setup_project(client, tmp_path, workspace)
    assert result["mode"] == "preview"
    assert result["written"] is False
    assert str(workspace) in result["config_content"]
    assert result["changes"]
    assert result["backups"] == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("client", ["codex", "claude-code"])
def test_install_is_idempotent_and_copies_bundled_skill(tmp_path, client, bundled_skill):
    workspace = tmp_path / "private work"
    first = setup.setup_project(client, tmp_path, workspace, write=True)
    config = Path(first["config_path"])
    skill = Path(first["skill_dest"])
    initial = config.read_bytes()
    for name, content in bundled_skill.items():
        assert (skill / name).read_bytes() == content
    manifest = json.loads((skill / setup._MANIFEST).read_text())
    assert manifest["owner"] == "aire.setup"
    second = setup.setup_project(client, tmp_path, workspace, write=True)
    assert second["changes"] == second["backups"] == []
    assert config.read_bytes() == initial
    assert not workspace.exists()
    assert not (tmp_path / ".aire-setup-backups").exists()


def test_codex_preserves_comments_settings_and_other_servers_and_backs_up(tmp_path):
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    original = (
        '# Existing project settings\nmodel = "chosen-model" # keep this\n\n'
        '[mcp_servers.other]\ncommand = "other-server" # server comment\n'
        'args = ["--flag"]\n\n[mcp_servers.other.env]\nTOKEN = "existing-secret"\n'
    )
    config.write_text(original)
    preview = setup.setup_project("codex", tmp_path, tmp_path / "work")
    assert config.read_text() == original
    assert "existing-secret" not in json.dumps(preview)
    result = setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    text = config.read_text()
    assert "# Existing project settings" in text
    assert '# keep this' in text
    assert '# server comment' in text
    parsed = tomllib.loads(text)
    assert parsed["model"] == "chosen-model"
    assert parsed["mcp_servers"]["other"]["env"]["TOKEN"] == "existing-secret"
    assert len(result["backups"]) == 1
    assert Path(result["backups"][0]).read_text() == original
    assert server_for("codex", config)["tool_timeout_sec"] == 240
    assert server_for("codex", config)["startup_timeout_sec"] == 30


def test_claude_preserves_other_servers_and_top_level_settings(tmp_path):
    config = tmp_path / ".mcp.json"
    original = {"mcpServers": {"other": {"command": "other", "args": ["hello"]}},
                "custom": {"setting": True}}
    config.write_text(json.dumps(original))
    setup.setup_project("claude-code", tmp_path, tmp_path / "work", write=True)
    actual = json.loads(config.read_text())
    assert actual["custom"] == original["custom"]
    assert actual["mcpServers"]["other"] == original["mcpServers"]["other"]
    assert actual["mcpServers"]["aire"]["type"] == "stdio"


def test_inline_codex_server_table_is_preserved(tmp_path):
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_text('mcp_servers = { other = { command = "other-tool" } } # keep inline\n')
    setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    parsed = tomllib.loads(config.read_text())
    assert parsed["mcp_servers"]["other"]["command"] == "other-tool"
    assert parsed["mcp_servers"]["aire"]["args"][1] == "aire"
    assert "# keep inline" in config.read_text()
    assert setup.setup_project("codex", tmp_path, tmp_path / "work")["changes"] == []


@pytest.mark.parametrize("client", ["codex", "claude-code"])
def test_paths_with_spaces_stay_individual_arguments_and_venv_is_not_resolved(
    tmp_path, monkeypatch, client,
):
    project = tmp_path / "a project"
    project.mkdir()
    interpreter = tmp_path / "native venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to(sys.executable)
    monkeypatch.setattr(setup.sys, "executable", str(interpreter))
    workspace = tmp_path / "a private workspace"
    result = setup.setup_project(client, project, workspace, write=True)
    server = server_for(client, Path(result["config_path"]))
    assert server["command"] == str(interpreter)
    assert server["args"] == ["-m", "aire", "--workspace", str(workspace), "mcp"]
    assert all(isinstance(value, str) for value in server["args"])
    if client == "codex":
        assert server["cwd"] == str(project)


@pytest.mark.parametrize("client", ["codex", "claude-code"])
def test_only_toolchain_allowlist_is_persisted(tmp_path, monkeypatch, client):
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", "/tools/Ghidra 12")
    monkeypatch.setenv("JAVA_HOME", "/tools/Java 21")
    monkeypatch.setenv("GHIDRA_SWIFT_DEMANGLER", "/tools/swift demangle")
    monkeypatch.setenv("AIRE_API_KEY", "aire-secret-never-write")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-secret-never-write")
    monkeypatch.setenv("UNRELATED_SECRET", "unrelated-secret-never-write")
    result = setup.setup_project(client, tmp_path, tmp_path / "work", write=True)
    server = server_for(client, Path(result["config_path"]))
    assert server["env"] == {name: os.environ[name] for name in setup._ENV_ALLOWLIST}
    all_content = json.dumps(result) + "".join(
        path.read_text() for path in tmp_path.rglob("*") if path.is_file()
    )
    for secret in ("aire-secret-never-write", "openai-secret-never-write", "unrelated-secret-never-write"):
        assert secret not in all_content
    assert "AIRE_API_KEY" not in all_content


@pytest.mark.parametrize("client", ["codex", "claude-code"])
def test_update_owned_server_drops_stale_env_and_preserves_policy(tmp_path, monkeypatch, client):
    monkeypatch.setenv("JAVA_HOME", "/initial/java")
    first = setup.setup_project(client, tmp_path, tmp_path / "old work", write=True)
    path = Path(first["config_path"])
    if client == "codex":
        content = path.read_text().replace('command = ', 'enabled = false # keep policy\ncommand = ', 1)
        content = content.replace('JAVA_HOME = "/initial/java"', 'JAVA_HOME = "/initial/java"\nAIRE_API_KEY = "stale-secret"')
        path.write_text(content)
    else:
        data = json.loads(path.read_text())
        data["mcpServers"]["aire"]["customPolicy"] = "keep"
        data["mcpServers"]["aire"]["env"]["AIRE_API_KEY"] = "stale-secret"
        path.write_text(json.dumps(data))
    monkeypatch.delenv("JAVA_HOME")
    result = setup.setup_project(client, tmp_path, tmp_path / "new work", write=True)
    server = server_for(client, path)
    assert server["env"] == {}
    assert server["args"][3] == str(tmp_path / "new work")
    assert "stale-secret" not in path.read_text()
    assert result["backups"]
    if client == "codex":
        assert server["enabled"] is False
        assert "# keep policy" in path.read_text()
    else:
        assert server["customPolicy"] == "keep"


@pytest.mark.parametrize("client", ["codex", "claude-code"])
def test_unrelated_same_named_server_is_never_overwritten(tmp_path, client):
    path = tmp_path / ".codex" / "config.toml" if client == "codex" else tmp_path / ".mcp.json"
    path.parent.mkdir(exist_ok=True)
    original = ('[mcp_servers.aire]\ncommand = "another-tool"\n' if client == "codex"
                else '{"mcpServers":{"aire":{"command":"another-tool"}}}')
    path.write_text(original)
    for write in (False, True):
        with pytest.raises(ValueError, match="unrelated MCP server"):
            setup.setup_project(client, tmp_path, tmp_path / "work", write=write)
        assert path.read_text() == original
    assert not (tmp_path / ".agents").exists()
    assert not (tmp_path / ".claude").exists()


@pytest.mark.parametrize("client,folder", [("codex", ".agents"), ("claude-code", ".claude")])
def test_unmanaged_same_named_skill_blocks_all_writes(tmp_path, client, folder):
    skill = tmp_path / folder / "skills" / "aire-investigate"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("User-authored instructions")
    with pytest.raises(ValueError, match="unmanaged"):
        setup.setup_project(client, tmp_path, tmp_path / "work", write=True)
    assert (skill / "SKILL.md").read_text() == "User-authored instructions"
    assert not (tmp_path / ".codex" / "config.toml").exists()
    assert not (tmp_path / ".mcp.json").exists()


def test_modified_managed_skill_is_preserved_without_config_changes(tmp_path):
    first = setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    skill_file = Path(first["skill_dest"]) / "SKILL.md"
    skill_file.write_text("Local changes")
    config = Path(first["config_path"])
    original = config.read_bytes()
    with pytest.raises(ValueError, match="was edited"):
        setup.setup_project("codex", tmp_path, tmp_path / "new work", write=True)
    assert skill_file.read_text() == "Local changes"
    assert config.read_bytes() == original
    assert not (tmp_path / ".aire-setup-backups").exists()


def test_skill_update_backs_up_prior_managed_files(tmp_path, bundled_skill):
    first = setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    old_skill = bundled_skill["SKILL.md"]
    bundled_skill["SKILL.md"] += b"\nUpdated workflow.\n"
    result = setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    assert (Path(first["skill_dest"]) / "SKILL.md").read_bytes() == bundled_skill["SKILL.md"]
    assert any(Path(path).read_bytes() == old_skill for path in result["backups"])
    assert setup.setup_project("codex", tmp_path, tmp_path / "work")["changes"] == []


def test_custom_codex_timeouts_are_preserved_and_previewed(tmp_path):
    first = setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    path = Path(first["config_path"])
    path.write_text(path.read_text().replace("startup_timeout_sec = 30", "startup_timeout_sec = 90 # custom")
                    .replace("tool_timeout_sec = 240", "tool_timeout_sec = 500"))
    result = setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    server = server_for("codex", path)
    preview = tomllib.loads(result["config_content"])["mcp_servers"]["aire"]
    assert server["startup_timeout_sec"] == preview["startup_timeout_sec"] == 90
    assert server["tool_timeout_sec"] == preview["tool_timeout_sec"] == 500
    assert "# custom" in path.read_text()
    assert result["changes"] == []


def test_retired_resource_can_be_reintroduced_without_losing_ownership(tmp_path, bundled_skill):
    bundled_skill["reference.txt"] = b"First version"
    first = setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    del bundled_skill["reference.txt"]
    setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    bundled_skill["reference.txt"] = b"Updated version"
    result = setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    assert (Path(first["skill_dest"]) / "reference.txt").read_bytes() == b"Updated version"
    assert any(Path(path).read_bytes() == b"First version" for path in result["backups"])


def test_symlink_to_user_settings_is_rejected_before_writing(tmp_path):
    project = tmp_path / "project"
    outside = tmp_path / "user config"
    project.mkdir()
    outside.mkdir()
    (outside / "config.toml").write_text("# User settings\n")
    (project / ".codex").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        setup.setup_project("codex", project, project / "work", write=True)
    assert (outside / "config.toml").read_text() == "# User settings\n"
    assert not (project / ".agents").exists()


@pytest.mark.parametrize("client,relative,content", [
    ("codex", ".codex/config.toml", "[broken"),
    ("claude-code", ".mcp.json", "{broken"),
    ("claude-code", ".mcp.json", "[]"),
])
def test_invalid_existing_config_is_preserved(tmp_path, client, relative, content):
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    with pytest.raises(ValueError):
        setup.setup_project(client, tmp_path, tmp_path / "work", write=True)
    assert path.read_text() == content


def test_atomic_replacement_keeps_existing_file_mode(tmp_path, monkeypatch):
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_text("# Existing\n")
    config.chmod(0o640)
    calls = []
    replace = setup.os.replace

    def record_replace(source, destination):
        assert Path(source).parent == Path(destination).parent
        calls.append(Path(destination))
        replace(source, destination)

    monkeypatch.setattr(setup.os, "replace", record_replace)
    result = setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    assert config in calls
    assert len(calls) == len(result["changes"]) + len(result["backups"])
    assert config.stat().st_mode & 0o777 == 0o640


def test_refuses_user_global_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(setup.Path, "home", lambda: tmp_path)
    with pytest.raises(ValueError, match="user-global"):
        setup.setup_project("codex", tmp_path, tmp_path / "work", write=True)
    assert list(tmp_path.iterdir()) == []


def test_unknown_client_does_not_write(tmp_path):
    with pytest.raises(ValueError, match="Supported setup clients"):
        setup.setup_project("unknown", tmp_path, tmp_path / "work", write=True)
    assert list(tmp_path.iterdir()) == []
