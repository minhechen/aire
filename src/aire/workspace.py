"""Local project, entity, evidence, and investigation persistence."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .models import Entity, Image, ToolResult


def encode(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


def stable_id(prefix: str, *parts: Any) -> str:
    return prefix + "_" + hashlib.sha256(encode(parts).encode()).hexdigest()[:24]


class Workspace:
    def __init__(self, root: Path | str):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(self.root / "workspace.sqlite3")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY, sha256 TEXT UNIQUE NOT NULL,
                manifest TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS entities (
                id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id)
                ON DELETE CASCADE, kind TEXT, name TEXT, value TEXT, data TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS entities_project ON entities(project_id,kind);
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id)
                ON DELETE CASCADE, question TEXT NOT NULL, status TEXT NOT NULL,
                report TEXT NOT NULL DEFAULT '{}', messages TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id)
                ON DELETE CASCADE, tool TEXT NOT NULL, params TEXT NOT NULL,
                result TEXT NOT NULL, digest TEXT NOT NULL, provenance TEXT NOT NULL,
                created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS case_evidence (
                case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
                PRIMARY KEY(case_id,evidence_id));
        """)
        self.fts = True
        try:
            self.db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5("
                            "entity_id UNINDEXED,project_id UNINDEXED,text)")
        except sqlite3.OperationalError:
            self.fts = False
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def project_path(self, project_id: str) -> Path:
        self.project(project_id)
        return self.root / "projects" / project_id

    def import_ipa(self, source: Path) -> dict[str, Any]:
        from .platforms.ios.importer import inspect_ipa

        source = source.expanduser().resolve(strict=True)
        with source.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        existing = self.db.execute("SELECT manifest FROM projects WHERE sha256=?", (digest,)).fetchone()
        if existing:
            return json.loads(existing[0])
        project_id = "ios_" + digest[:20]
        staging = self.root / "staging" / uuid.uuid4().hex
        target = self.root / "projects" / project_id
        staging.mkdir(parents=True)
        try:
            result = inspect_ipa(source, staging / "bundle")
            if result.input_sha256 != digest:
                raise ValueError("The source IPA changed during import")
            image_ids = {image.id: stable_id("img", project_id, image.id) for image in result.images}
            for image in result.images:
                image.id = image_ids[image.id]
            for entity in result.entities:
                entity.id = stable_id("ent", project_id, entity.id)
                if entity.image_id:
                    entity.image_id = image_ids[entity.image_id]
            manifest = result.to_dict()
            manifest.update(id=project_id, schema_version=1, imported_at=utcnow(),
                            aire_version=__version__, source_name=source.name)
            # Entities live in the database; avoid duplicating large indexes in the manifest.
            manifest.pop("entities", None)
            if target.exists():
                raise ValueError("Project directory exists without a matching database record")
            target.parent.mkdir(parents=True, exist_ok=True)
            staging.rename(target)
            with self.db:
                self.db.execute("INSERT INTO projects VALUES (?,?,?,?)",
                                (project_id, digest, encode(manifest), utcnow()))
                self.add_entities(project_id, result.entities, commit=False)
            (target / "manifest.json").write_text(encode(manifest) + "\n", encoding="utf-8")
            return manifest
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            # A failed transaction must not leave a half-imported project.
            if target.exists() and not self.db.execute(
                "SELECT 1 FROM projects WHERE id=?", (project_id,)
            ).fetchone():
                shutil.rmtree(target)
            raise

    def project(self, project_id: str) -> dict[str, Any]:
        row = self.db.execute("SELECT manifest FROM projects WHERE id=?", (project_id,)).fetchone()
        if row is None:
            raise ValueError(f"Unknown project: {project_id}")
        return json.loads(row[0])

    def projects(self) -> list[dict[str, Any]]:
        return [json.loads(r[0]) for r in self.db.execute(
            "SELECT manifest FROM projects ORDER BY created_at DESC")]

    def images(self, project_id: str) -> list[Image]:
        return [Image(**image) for image in self.project(project_id)["images"]]

    def image(self, project_id: str, image_id: str) -> Image:
        for image in self.images(project_id):
            if image.id == image_id:
                return image
        raise ValueError(f"Unknown image: {image_id}")

    def add_entities(self, project_id: str, entities: list[Entity], *, commit=True) -> None:
        for entity in entities:
            self.db.execute("INSERT OR REPLACE INTO entities VALUES (?,?,?,?,?,?)",
                            (entity.id, project_id, entity.kind, entity.name,
                             entity.value, encode(entity.to_dict())))
            if self.fts:
                self.db.execute("DELETE FROM search WHERE entity_id=?", (entity.id,))
                text = " ".join(str(s or "") for s in (entity.name, entity.value, entity.path))
                split = re.sub(r"([a-z])([A-Z])", r"\1 \2", text).replace("_", " ").replace(":", " ")
                self.db.execute("INSERT INTO search VALUES (?,?,?)", (entity.id, project_id, text + " " + split))
        if commit:
            self.db.commit()

    def entity(self, project_id: str, entity_id: str) -> Entity:
        row = self.db.execute("SELECT data FROM entities WHERE project_id=? AND id=?",
                              (project_id, entity_id)).fetchone()
        if row is None:
            raise ValueError(f"Unknown entity: {entity_id}")
        return Entity(**json.loads(row[0]))

    def search(self, project_id: str, query: str, kinds: list[str] | None = None,
               limit: int = 20) -> list[dict[str, Any]]:
        self.project(project_id)
        limit = max(1, min(int(limit), 50))
        if not query or len(query) > 512:
            raise ValueError("Search must contain 1–512 characters")
        terms = re.findall(r"\w+", query, re.UNICODE)[:12]
        if not terms:
            return []
        found: dict[str, dict[str, Any]] = {}
        if self.fts:
            fts_query = " OR ".join('"' + term.replace('"', '""') + '"' for term in terms)
            for row in self.db.execute(
                "SELECT e.data FROM search s JOIN entities e ON e.id=s.entity_id "
                "WHERE search MATCH ? AND s.project_id=? ORDER BY rank LIMIT ?",
                (fts_query, project_id, limit * 4),
            ):
                item = json.loads(row[0])
                if not kinds or item["kind"] in kinds:
                    found[item["id"]] = item
        # Two-character Chinese labels and partial selectors require substring lookup.
        clauses = ["(name LIKE ? ESCAPE '\\' OR value LIKE ? ESCAPE '\\')" for _ in terms]
        args: list[Any] = [project_id]
        for term in terms:
            escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            args.extend([f"%{escaped}%", f"%{escaped}%"])
        args.append(limit * 4)
        for row in self.db.execute(
            "SELECT data FROM entities WHERE project_id=? AND (" + " OR ".join(clauses) + ") LIMIT ?",
            args,
        ):
            item = json.loads(row[0])
            if not kinds or item["kind"] in kinds:
                found.setdefault(item["id"], item)
        values = list(found.values())[:limit]
        for item in values:
            if item.get("value"):
                item["value"] = item["value"][:1600]
        return values

    def new_case(self, project_id: str, question: str) -> str:
        self.project(project_id)
        case_id = "case_" + uuid.uuid4().hex[:16]
        now = utcnow()
        with self.db:
            self.db.execute("INSERT INTO cases (id,project_id,question,status,created_at,updated_at) "
                            "VALUES (?,?,?,'running',?,?)", (case_id, project_id, question, now, now))
        return case_id

    def save_case(self, case_id: str, report: dict[str, Any]) -> None:
        report = report.copy()
        messages = report.pop("messages", [])
        with self.db:
            self.db.execute("UPDATE cases SET status=?,report=?,messages=?,updated_at=? WHERE id=?",
                            (report.get("status", "complete"), encode(report), encode(messages),
                             utcnow(), case_id))

    def case(self, case_id: str) -> dict[str, Any]:
        row = self.db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if row is None:
            raise ValueError(f"Unknown case: {case_id}")
        result = dict(row)
        result["report"] = json.loads(result["report"])
        result["messages"] = json.loads(result["messages"])
        return result

    def evidence(self, evidence_id: str) -> dict[str, Any]:
        row = self.db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if row is None:
            raise ValueError(f"Unknown evidence: {evidence_id}")
        result = dict(row)
        for key in ("params", "result", "provenance"):
            result[key] = json.loads(result[key])
        return result

    def evidence_for_case(self, case_id: str) -> list[dict[str, Any]]:
        return [self.evidence(row[0]) for row in self.db.execute(
            "SELECT evidence_id FROM case_evidence WHERE case_id=? ORDER BY rowid", (case_id,))]

    def record_evidence(self, project_id: str, case_id: str, tool: str, params: dict,
                        result: ToolResult) -> str:
        raw = {"status": result.status, "data": result.data, "error": result.error}
        digest = hashlib.sha256(encode(raw).encode()).hexdigest()
        eid = stable_id("ev", project_id, tool, params, digest)
        provenance = {"aire_version": __version__, "schema_version": 1,
                      "input_sha256": self.project(project_id)["input_sha256"]}
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO evidence VALUES (?,?,?,?,?,?,?,?)",
                            (eid, project_id, tool, encode(params), encode(raw), digest,
                             encode(provenance), utcnow()))
            self.db.execute("INSERT OR IGNORE INTO case_evidence VALUES (?,?)", (case_id, eid))
        return eid

    def delete_project(self, project_id: str) -> None:
        path = self.project_path(project_id)
        case_ids = [row[0] for row in self.db.execute("SELECT id FROM cases WHERE project_id=?", (project_id,))]
        with self.db:
            if self.fts:
                self.db.execute("DELETE FROM search WHERE project_id=?", (project_id,))
            self.db.execute("DELETE FROM projects WHERE id=?", (project_id,))
        shutil.rmtree(path, ignore_errors=True)
        for case_id in case_ids:
            for suffix in ("html", "md", "json"):
                (self.root / "reports" / f"{case_id}.{suffix}").unlink(missing_ok=True)
