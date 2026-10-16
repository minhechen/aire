"""Portable, JSON-serializable analysis contracts."""

from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = 1


@dataclass
class Entity:
    id: str
    kind: str
    name: str
    image_id: str | None = None
    address: int | None = None
    file_offset: int | None = None
    path: str | None = None
    value: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Image:
    id: str
    path: str
    sha256: str
    architecture: str
    status: str = "ready"
    encrypted: bool = False
    encryption_ranges: list[dict[str, int]] = field(default_factory=list)
    imagebase: int = 0
    uuid: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ImportResult:
    app_name: str
    bundle_id: str
    input_sha256: str
    images: list[Image] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolResult:
    status: str
    data: dict[str, Any] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)
    error: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
