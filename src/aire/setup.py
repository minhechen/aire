"""Preview and install project-scoped agent configuration and investigation skills."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path, PurePosixPath
from uuid import uuid4

import tomlkit
from tomlkit.items import InlineTable

_ENV_ALLOWLIST = ("GHIDRA_INSTALL_DIR", "JAVA_HOME", "GHIDRA_SWIFT_DEMANGLER")
_SKILL_NAME = "aire-investigate"
_MANIFEST = ".aire-managed.json"
_OWNER = "aire.setup"


def _bundled_skill() -> dict[str, bytes]:
    """Read package data without relying on an editable source checkout."""
    root = resources.files("aire").joinpath("skills", _SKILL_NAME)
    result: dict[str, bytes] = {}

    def visit(directory, prefix=""):
        for item in sorted(directory.iterdir(), key=lambda entry: entry.name):
            name = f"{prefix}{item.name}"
            if item.is_dir():
                visit(item, name + "/")
            elif item.is_file():
                result[name] = item.read_bytes()

    try:
        visit(root)
    except (FileNotFoundError, NotADirectoryError) as exc:
        raise RuntimeError("The installed aire package does not contain its investigation skill") from exc
    if "SKILL.md" not in result:
        raise RuntimeError("The installed aire package does not contain its investigation skill")
    return result


def _local_path(project: Path, target: Path) -> None:
    """Never follow a project configuration symlink into user-global files."""
    relative = target.relative_to(project)
    current = project
    for index, part in enumerate(relative.parts):
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Refusing project setup through a symlink: {current}")
        if current.exists() and index < len(relative.parts) - 1 and not current.is_dir():
            raise ValueError(f"Expected a project-local directory: {current}")


def _read_file(project: Path, target: Path) -> bytes | None:
    _local_path(project, target)
    if target.exists():
        if not target.is_file():
            raise ValueError(f"Expected a project-local file: {target}")
        return target.read_bytes()
    return None


def _aire_server(server) -> bool:
    """The module launch form is an ownership marker, independent of its venv path."""
    if not isinstance(server, Mapping):
        return False
    args = server.get("args")
    return (
        isinstance(server.get("command"), str)
        and bool(server["command"])
        and isinstance(args, Sequence) and not isinstance(args, (str, bytes))
        and len(args) == 5
        and args[:3] == ["-m", "aire", "--workspace"]
        and isinstance(args[3], str)
        and Path(args[3]).is_absolute()
        and args[4] == "mcp"
        and "url" not in server
    )


def _codex_config(original: bytes | None, server: dict) -> bytes:
    try:
        document = tomlkit.parse(original.decode("utf-8") if original is not None else "")
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Existing .codex/config.toml is not valid UTF-8 TOML") from exc
    servers = document.get("mcp_servers")
    if servers is None:
        document["mcp_servers"] = tomlkit.table()
        servers = document["mcp_servers"]
    if not isinstance(servers, Mapping):
        raise ValueError("Existing mcp_servers setting is not a table")  # noqa: TRY004
    existing = servers.get("aire")
    if "aire" in servers and not _aire_server(existing):
        raise ValueError("An unrelated MCP server named 'aire' already exists; it was not changed")
    if existing is None:
        servers["aire"] = tomlkit.inline_table() if isinstance(servers, InlineTable) else tomlkit.table()
        existing = servers["aire"]
    # Keep user-selected approval, enabled, timeout, and tool settings intact.
    for key, value in server.items():
        if key in {"startup_timeout_sec", "tool_timeout_sec"} and key in existing:
            continue
        if existing.get(key) != value:
            existing[key] = value
    # Do not retain stale explicit environment forwarding from an older setup.
    if "env_vars" in existing:
        del existing["env_vars"]
    return tomlkit.dumps(document).encode("utf-8")


def _claude_config(original: bytes | None, server: dict) -> bytes:
    try:
        document = json.loads(original) if original is not None else {}
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Existing .mcp.json is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("Existing .mcp.json must contain a JSON object")  # noqa: TRY004
    servers = document.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError("Existing mcpServers setting must contain a JSON object")  # noqa: TRY004
    existing = servers.get("aire")
    if "aire" in servers and not _aire_server(existing):
        raise ValueError("An unrelated MCP server named 'aire' already exists; it was not changed")
    merged = dict(existing or {})
    merged.update(server)
    merged.pop("env_vars", None)
    servers["aire"] = merged
    # Avoid a formatting-only rewrite when a pre-existing JSON document already matches.
    if original is not None and json.loads(original) == document:
        return original
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _skill_plan(project: Path, destination: Path, bundled: dict[str, bytes]) -> dict[Path, bytes]:
    _local_path(project, destination)
    manifest_path = destination / _MANIFEST
    managed_files = {}
    if destination.exists():
        if not destination.is_dir():
            raise ValueError(f"The skill destination is not a directory: {destination}")
        original = _read_file(project, manifest_path)
        try:
            manifest = json.loads(original) if original is not None else {}
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Existing aire-investigate skill has no valid aire ownership manifest") from exc
        if (not isinstance(manifest, dict) or manifest.get("owner") != _OWNER
                or manifest.get("schema_version") != 1 or not isinstance(manifest.get("files"), dict)):
            raise ValueError("An unmanaged 'aire-investigate' skill already exists; it was not changed")
        for name, digest in manifest["files"].items():
            if not isinstance(name, str) or not isinstance(digest, str):
                raise ValueError(  # noqa: TRY004
                    "The existing skill ownership manifest contains invalid file metadata"
                )
            parts = PurePosixPath(name)
            if parts.is_absolute() or ".." in parts.parts or not parts.parts or "\\" in name:
                raise ValueError("The existing skill ownership manifest contains an unsafe path")
            installed = _read_file(project, destination.joinpath(*parts.parts))
            if installed is None or hashlib.sha256(installed).hexdigest() != digest:
                raise ValueError(f"The installed aire skill was edited; refusing to overwrite {name}")
            managed_files[name] = digest
        for name in bundled:
            target = destination / name
            if name not in manifest["files"] and target.exists():
                raise ValueError(f"An unmanaged skill file already exists; it was not changed: {target}")
    manifest = {
        "owner": _OWNER,
        "schema_version": 1,
        # Retain ownership of retired resources that are left in place, so a later
        # bundle can safely reintroduce them without claiming a user's own file.
        "files": dict(sorted({**managed_files, **{
            name: hashlib.sha256(content).hexdigest() for name, content in bundled.items()
        }}.items())),
    }
    files = {destination / name: content for name, content in bundled.items()}
    files[manifest_path] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    return files


def _atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", dir=path.parent, delete=False) as temp:
            temp_path = Path(temp.name)
            temp.write(content)
            temp.flush()
            os.fsync(temp.fileno())
        temp_path.chmod(mode)
        os.replace(temp_path, path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def setup_project(
    client: str, project_dir: Path, workspace_root: Path, *, write: bool = False,
) -> dict:
    """Preview local MCP/skill setup; write only when explicitly requested.

    Existing unrelated servers, host settings, and TOML comments are preserved. An
    existing server named ``aire`` must use the aire module launch form, and an
    existing investigation skill must have an intact aire ownership manifest.
    """
    client = {"claude": "claude-code", "claude_code": "claude-code"}.get(client, client)
    if client not in {"codex", "claude-code"}:
        raise ValueError("Supported setup clients are 'codex' and 'claude-code'")
    project = Path(project_dir).expanduser().resolve()
    workspace = Path(workspace_root).expanduser().resolve()
    if not project.is_dir():
        raise ValueError(f"Project directory does not exist: {project}")
    if project == Path.home().resolve() or project == Path(project.anchor):
        raise ValueError("Choose a project directory; user-global setup is not supported")
    # Do not resolve interpreter symlinks: a venv's path selects its site-packages,
    # and can also select the correct architecture for a native Ghidra/JVM install.
    interpreter = os.path.abspath(sys.executable)
    server = {
        "command": interpreter,
        "args": ["-m", "aire", "--workspace", str(workspace), "mcp"],
        "env": {name: os.environ[name] for name in _ENV_ALLOWLIST if os.environ.get(name)},
    }
    if client == "codex":
        server["cwd"] = str(project)
        server["startup_timeout_sec"] = 30
        server["tool_timeout_sec"] = 240
        config_path = project / ".codex" / "config.toml"
        skill_dest = project / ".agents" / "skills" / _SKILL_NAME
        merge = _codex_config
        next_steps = [
            "Open this directory as a trusted Codex project, then restart the agent.",
            "Check /mcp for aire and invoke $aire-investigate with your IPA path and question.",
        ]
    else:
        server["type"] = "stdio"
        config_path = project / ".mcp.json"
        skill_dest = project / ".claude" / "skills" / _SKILL_NAME
        merge = _claude_config
        next_steps = [
            "Open Claude Code in this project and approve the project-scoped aire MCP server.",
            "Check /mcp for aire and invoke /aire-investigate with your IPA path and question.",
        ]

    original_config = _read_file(project, config_path)
    merged_config = merge(original_config, server)
    if client == "codex":
        effective = tomlkit.parse(merged_config.decode("utf-8"))["mcp_servers"]["aire"]
        preview = tomlkit.document()
        preview["mcp_servers"] = {"aire": {key: effective[key] for key in server}}
        config_content = tomlkit.dumps(preview)
    else:
        config_content = json.dumps({"mcpServers": {"aire": server}}, ensure_ascii=False, indent=2) + "\n"
    files = {config_path: merged_config}
    files.update(_skill_plan(project, skill_dest, _bundled_skill()))
    originals = {path: _read_file(project, path) for path in files}
    changes = {path: content for path, content in files.items() if originals[path] != content}
    backups: list[str] = []
    if write and changes:
        backup_root = project / ".aire-setup-backups" / (
            datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + "-" + uuid4().hex[:8]
        )
        # Validate all destinations and create all backups before modifying any originals.
        for path in changes:
            if originals[path] is not None:
                backup = backup_root / path.relative_to(project)
                _local_path(project, backup)
                _atomic_write(backup, originals[path])
                backups.append(str(backup))
        for path, content in changes.items():
            _local_path(project, path)
            mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
            _atomic_write(path, content, mode)

    return {
        "client": client,
        "mode": "write" if write else "preview",
        "project_dir": str(project),
        "workspace_root": str(workspace),
        "config_path": str(config_path),
        "config_content": config_content,
        "config_content_scope": "aire server entry; unrelated settings are preserved",
        "skill_dest": str(skill_dest),
        "skill_files": sorted(_SKILL_NAME + "/" + path.relative_to(skill_dest).as_posix()
                             for path in files if path != config_path),
        "changes": [str(path) for path in changes],
        "backups": backups,
        "written": bool(write),
        "next_steps": next_steps,
    }
