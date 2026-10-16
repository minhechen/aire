"""Safe IPA extraction and bounded iOS bundle inventory."""

from __future__ import annotations

import hashlib
import json
import plistlib
import stat
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.parsers.expat import ExpatError

from aire.models import Entity, Image, ImportResult
from aire.platforms.ios.macho import MachOFormatError, inspect_macho, is_macho, stable_id


class IPAImportError(ValueError):
    """An archive is unsafe, malformed, or not an iOS application package."""


@dataclass(frozen=True)
class ImportLimits:
    max_files: int = 25000
    max_uncompressed_bytes: int = 4 * 1024**3
    max_file_bytes: int = 1024**3
    max_compression_ratio: int = 1000
    max_resource_bytes: int = 2 * 1024**2
    max_resource_total_bytes: int = 32 * 1024**2
    max_entities: int = 200000


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _members(archive: zipfile.ZipFile, limits: ImportLimits):
    entries = archive.infolist()
    if not entries or len(entries) > limits.max_files:
        raise IPAImportError(f"Archive exceeds the {limits.max_files} entry limit or is empty")
    total, names, result = 0, {}, []
    for entry in entries:
        raw = entry.orig_filename
        if not raw or "\0" in raw or "\\" in raw or raw.startswith("/"):
            raise IPAImportError(f"Unsafe archive path: {raw!r}")
        parts = raw.rstrip("/").split("/")
        if any(part in {"", ".", ".."} or ":" in part for part in parts):
            raise IPAImportError(f"Unsafe archive path: {raw!r}")
        key = unicodedata.normalize("NFC", "/".join(parts)).casefold()
        if key in names:
            raise IPAImportError(f"Duplicate or case-colliding archive path: {raw!r}")
        names[key] = entry.is_dir()
        unix_mode = entry.external_attr >> 16
        file_kind = stat.S_IFMT(unix_mode)
        if file_kind and file_kind not in {stat.S_IFREG, stat.S_IFDIR}:
            raise IPAImportError(f"Archive contains a symlink or special file: {raw!r}")
        if stat.S_ISDIR(unix_mode) and not entry.is_dir():
            raise IPAImportError(f"Conflicting archive entry type: {raw!r}")
        if entry.flag_bits & 1:
            raise IPAImportError("Password-encrypted ZIP entries are unsupported")
        if entry.file_size < 0 or entry.file_size > limits.max_file_bytes:
            raise IPAImportError(f"Archive member exceeds file size limit: {raw!r}")
        if (
            entry.file_size > 1024**2
            and entry.file_size > max(1, entry.compress_size) * limits.max_compression_ratio
        ):
            raise IPAImportError(f"Archive member exceeds compression ratio limit: {raw!r}")
        total += entry.file_size
        if total > limits.max_uncompressed_bytes:
            raise IPAImportError("Archive exceeds total extracted size limit")
        result.append((entry, Path(*parts), key))
    for _, _, key in result:
        parts = key.split("/")
        if any(names.get("/".join(parts[:index])) is False for index in range(1, len(parts))):
            raise IPAImportError("Archive file is used as a parent directory")
    return result


def _extract(source: Path, destination: Path, limits: ImportLimits):
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise IPAImportError("Extraction destination must be an empty directory")
    try:
        with zipfile.ZipFile(source) as archive:
            entries = _members(archive, limits)  # Validate the entire directory before writing.
            destination.mkdir(parents=True, exist_ok=True)
            total = 0
            for entry, relative, _ in entries:
                target = destination / relative
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(entry) as reader, target.open("xb") as writer:
                    for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                        written += len(chunk)
                        total += len(chunk)
                        if (
                            written > min(entry.file_size, limits.max_file_bytes)
                            or total > limits.max_uncompressed_bytes
                        ):
                            raise IPAImportError(
                                "Extracted data exceeds declared size or extraction limit"
                            )
                        writer.write(chunk)
                if written != entry.file_size:
                    raise IPAImportError(f"ZIP member size mismatch: {entry.filename!r}")
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as error:
        raise IPAImportError(f"Unable to extract IPA: {error}") from error


def _read_plist(path: Path, limits: ImportLimits) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > limits.max_resource_bytes:
        return {}
    try:
        result = plistlib.loads(path.read_bytes())
        return result if isinstance(result, dict) else {}
    except (
        plistlib.InvalidFileException,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
        ExpatError,
    ):
        return {}


def _flatten(value: Any, prefix: str = "", depth: int = 0):
    if depth > 20:
        return
    if isinstance(value, dict):
        for key, item in list(value.items())[:10000]:
            key = str(key).encode("utf-8", "backslashreplace").decode("utf-8")
            yield from _flatten(item, f"{prefix}.{key}" if prefix else key, depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value[:10000]):
            yield from _flatten(item, f"{prefix}[{index}]", depth + 1)
    elif isinstance(value, (str, bool, int, float)) and len(str(value)) <= 8192:
        yield prefix, str(value).encode("utf-8", "backslashreplace").decode("utf-8")


def _text(raw: bytes) -> str | None:
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16")
        text = raw.decode("utf-8-sig")
        if "\0" not in text:
            return text
    except UnicodeDecodeError:
        pass
    return None


def inspect_ipa(path: Path, destination: Path, limits: ImportLimits | None = None) -> ImportResult:
    """Extract and inventory an IPA in a new, caller-owned staging directory.

    The original archive is read-only. Unsafe paths and symlinks are rejected
    before extraction. On an extraction or package-validation failure, callers
    may delete the staging directory; no source material is modified.
    """
    path, destination, limits = Path(path), Path(destination), limits or ImportLimits()
    if not path.is_file():
        raise IPAImportError(f"IPA does not exist: {path}")
    if destination.is_symlink():
        raise IPAImportError("Extraction destination must not be a symlink")
    input_digest = _sha256(path)
    _extract(path, destination, limits)
    payload = destination / "Payload"
    apps = sorted(payload.glob("*.app")) if payload.is_dir() else []
    if len(apps) != 1 or not apps[0].is_dir():
        raise IPAImportError("Expected exactly one Payload/*.app bundle")
    app = apps[0]
    info = _read_plist(app / "Info.plist", limits)
    app_name = str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or app.stem)
    bundle_id = str(info.get("CFBundleIdentifier") or "unknown")
    executable_name = info.get("CFBundleExecutable")
    warnings, images, entities = [], [], []
    if not info:
        warnings.append("Main Info.plist is missing, invalid, or above the resource size limit")
    if not isinstance(executable_name, str) or Path(executable_name).name != executable_name:
        warnings.append("Main bundle executable is missing or invalid in Info.plist")
        main_binary = None
    else:
        main_binary = app / executable_name
        if not main_binary.is_file():
            warnings.append("Declared main bundle executable is missing")
    files = sorted(p for p in app.rglob("*") if p.is_file())
    resource_total, resource_count = 0, 0
    unsupported = set()
    for file in files:
        relative = file.relative_to(destination).as_posix()
        with file.open("rb") as handle:
            magic = handle.read(4)
        if is_macho(magic):
            role = "main" if file == main_binary else "binary"
            if role != "main" and any(p.endswith(".framework") for p in file.parts):
                role = "framework"
            elif role != "main" and any(p.endswith(".appex") for p in file.parts):
                role = "extension"
            try:
                found_images, found_entities, notes = inspect_macho(file, relative, role)
                images.extend(found_images)
                remaining = max(0, limits.max_entities - len(entities))
                entities.extend(found_entities[:remaining])
                warnings.extend(notes)
            except MachOFormatError as error:
                digest = _sha256(file)
                images.append(
                    Image(
                        stable_id(relative, digest, 0),
                        relative,
                        digest,
                        "unknown",
                        status="invalid",
                        details={"role": role, "error": str(error)},
                    )
                )
                warnings.append(f"{relative}: invalid Mach-O: {error}")
            continue
        if file == main_binary:
            warnings.append(f"{relative}: declared executable is not a recognized Mach-O binary")
        lower_path = relative.lower()
        if "flutter_assets/" in lower_path or lower_path.endswith("kernel_blob.bin"):
            unsupported.add("Flutter")
        if lower_path.endswith(("main.jsbundle", ".hbc")):
            unsupported.add("React Native")
        if lower_path.endswith("global-metadata.dat"):
            unsupported.add("Unity/IL2CPP")
        size = file.stat().st_size
        if (
            size > limits.max_resource_bytes
            or resource_total + size > limits.max_resource_total_bytes
        ):
            if file.suffix.lower() in {".plist", ".strings", ".json", ".txt", ".xml"}:
                warnings.append(f"{relative}: resource omitted by indexing size limit")
            continue
        suffix = file.suffix.lower()
        if suffix not in {
            ".plist",
            ".strings",
            ".stringsdict",
            ".json",
            ".txt",
            ".xml",
            ".html",
            ".htm",
            ".js",
            ".css",
            ".csv",
            ".xcprivacy",
            ".entitlements",
        }:
            continue
        raw = file.read_bytes()
        resource_total += size
        resource_count += 1
        content: Any = None
        if suffix in {".plist", ".strings", ".stringsdict", ".xcprivacy", ".entitlements"}:
            try:
                content = plistlib.loads(raw)
            except (
                plistlib.InvalidFileException,
                ValueError,
                TypeError,
                OverflowError,
                RecursionError,
                ExpatError,
            ):
                pass
        text = _text(raw) if content is None else None
        if content is None and suffix == ".json" and text is not None:
            try:
                content = json.loads(text)
            except (ValueError, RecursionError):
                pass
        pairs = list(_flatten(content)) if content is not None else []
        if not pairs and text:
            # OpenStep .strings is deliberately parsed as text, preserving the
            # source line instead of pretending to fully support its grammar.
            pairs = [
                (f"line:{index}", line.strip())
                for index, line in enumerate(text.splitlines(), 1)
                if 2 <= len(line.strip()) <= 8192
            ][:10000]
        resource_digest = hashlib.sha256(raw).hexdigest()
        for key, value in pairs:
            if len(entities) >= limits.max_entities:
                break
            if not value.strip():
                continue
            line_number = None
            if key.startswith("line:"):
                line_number = int(key.split(":", 1)[1])
            entities.append(
                Entity(
                    stable_id(input_digest, relative, key, value),
                    "resource",
                    key,
                    path=relative,
                    value=value,
                    metadata={
                        "source": "bundle_resource",
                        "format": suffix.lstrip("."),
                        "key": key,
                        "line": line_number,
                        "sha256": resource_digest,
                    },
                )
            )
    if not images:
        warnings.append("No Mach-O images were found; only resource evidence is available")
    if len(entities) >= limits.max_entities:
        warnings.append(f"Entity inventory truncated at {limits.max_entities} entries")
    if unsupported:
        warnings.append(
            f"Specialized runtime assets detected ({', '.join(sorted(unsupported))}); native inventory does not explain all application logic"
        )
    # Framework presence is a useful additional clue even in stripped images.
    framework_names = sorted(
        {
            parent.name
            for file in files
            for parent in file.parents
            if parent != app and parent.name.endswith(".framework")
        }
    )
    return ImportResult(
        app_name,
        bundle_id,
        input_digest,
        images,
        entities,
        list(dict.fromkeys(warnings)),
        {
            "platform": "ios",
            "bundle_path": app.relative_to(destination).as_posix(),
            "executable": main_binary.relative_to(destination).as_posix() if main_binary else None,
            "bundle_info": {
                key: str(info[key])
                for key in (
                    "CFBundleIdentifier",
                    "CFBundleName",
                    "CFBundleDisplayName",
                    "CFBundleExecutable",
                    "CFBundleShortVersionString",
                    "CFBundleVersion",
                    "MinimumOSVersion",
                )
                if key in info
            },
            "file_count": len(files),
            "resource_files_indexed": resource_count,
            "resource_bytes_indexed": resource_total,
            "frameworks": framework_names,
            "unsupported_runtimes": sorted(unsupported),
            "static_inventory_only": True,
        },
    )
