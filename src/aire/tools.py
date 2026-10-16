"""Read-only investigation tools with persisted provenance."""

from __future__ import annotations

import time
from typing import Any

from .models import Entity, ToolResult
from .workspace import Workspace, stable_id


def _schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties,
                           "required": required, "additionalProperties": False}}}


class Toolbox:
    def __init__(self, workspace: Workspace, project_id: str, case_id: str,
                 timeout: float = 120, total_seconds: float | None = None):
        self.workspace = workspace
        self.project_id = project_id
        self.case_id = case_id
        self.timeout = timeout
        self.deadline = time.monotonic() + (total_seconds if total_seconds is not None else timeout)
        self.backends: dict[str, Any] = {}
        self.workspace.project(project_id)
        if self.workspace.case(case_id)["project_id"] != project_id:
            raise ValueError("Case belongs to another project")

    @property
    def evidence_ids(self) -> set[str]:
        return {item["id"] for item in self.workspace.evidence_for_case(self.case_id)}

    @staticmethod
    def specs() -> list[dict]:
        text = {"type": "string"}
        entity = {"entity_id": text}
        return [
            _schema("list_images", "List binary images, architectures, and analysis limitations.", {}, []),
            _schema("search_entities", "Search strings/resources/symbols/classes/selectors/functions. "
                    "Names and string hits are candidates, not proof of feature behavior.",
                    {"query": text, "kinds": {"type": "array", "items": text},
                     "limit": {"type": "integer", "minimum": 1, "maximum": 30}}, ["query"]),
            _schema("analyze_image", "Build a persistent Ghidra index for one unencrypted image. "
                    "Use before code investigation. May be unavailable or partial.", {"image_id": text}, ["image_id"]),
            _schema("read_resource", "Read an indexed resource observation with its package location.", entity, ["entity_id"]),
            _schema("get_function", "Get function metadata near an indexed code address.", entity, ["entity_id"]),
            _schema("get_xrefs", "Find machine-code references to/from an indexed address.",
                    {**entity, "direction": {"type": "string", "enum": ["to", "from", "both"]}}, ["entity_id"]),
            _schema("get_calls", "Get observed callsites. Indirect call targets may remain unknown.", entity, ["entity_id"]),
            _schema("decompile", "Get approximate pseudocode near an indexed code address, never original source.", entity, ["entity_id"]),
            _schema("get_dispatch_candidates", "Find declared methods matching a recovered selector. "
                    "These are candidates, not confirmed call targets; receiver analysis is unavailable.",
                    {"image_id": text, "selector": text}, ["image_id", "selector"]),
        ]

    def call(self, name: str, arguments: dict) -> ToolResult:
        known = {item["function"]["name"]: item["function"]["parameters"] for item in self.specs()}
        if name not in known:
            return ToolResult("error", error={"code": "unknown_tool", "message": name})
        schema = known[name]
        if not isinstance(arguments, dict) or any(k not in schema["properties"] for k in arguments):
            return ToolResult("error", error={"code": "invalid_arguments", "message": "Unexpected arguments"})
        for key in schema["required"]:
            if key not in arguments:
                return ToolResult("error", error={"code": "invalid_arguments", "message": f"Missing {key}"})
        for key, value in arguments.items():
            expected = schema["properties"][key]["type"]
            if ((expected == "string" and not isinstance(value, str)) or
                (expected == "integer" and (not isinstance(value, int) or isinstance(value, bool))) or
                (expected == "array" and (not isinstance(value, list) or
                                         not all(isinstance(v, str) for v in value)))):
                return ToolResult("error", error={"code": "invalid_arguments", "message": f"Invalid {key}"})
        try:
            result = self._call(name, arguments)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            result = ToolResult("error", error={"code": "tool_error", "message": str(exc)[:1000]})
        eid = self.workspace.record_evidence(self.project_id, self.case_id, name, arguments, result)
        result.evidence_ids = [eid]
        return result

    def _call(self, name: str, args: dict) -> ToolResult:
        if name == "list_images":
            project = self.workspace.project(self.project_id)
            return ToolResult("ok", {"images": project["images"], "warnings": project["warnings"],
                                     "input_sha256": project["input_sha256"]})
        if name == "search_entities":
            matches = self.workspace.search(self.project_id, args["query"], args.get("kinds"),
                                            min(args.get("limit", 20), 30))
            return ToolResult("ok", {"matches": matches, "scope": "Currently indexed entities only",
                                     "limitation": "No matches does not establish absence."})
        if name == "analyze_image":
            image = self.workspace.image(self.project_id, args["image_id"])
            backend = self._backend(image.id)
            if isinstance(backend, ToolResult):
                return backend
            result = self._query(backend, "analyze")
            if result.status not in ("ok", "partial"):
                return result
            count, offset, truncated = 0, 0, False
            while True:
                functions = self._query(backend, "functions", limit=5000, offset=offset)
                self._ingest(image.id, functions.data)
                count += len(functions.data.get("functions", []))
                next_offset = functions.data.get("next_offset")
                if next_offset is None or count >= 50000 or functions.status not in ("ok", "partial"):
                    truncated = next_offset is not None or functions.status not in ("ok", "partial")
                    break
                if not isinstance(next_offset, int) or next_offset <= offset:
                    truncated = True
                    break
                offset = next_offset
            methods = self._query(backend, "objc_methods", limit=5000)
            self._ingest(image.id, methods.data)
            return ToolResult("partial" if truncated or methods.status != "ok" else result.status,
                              {"image_id": image.id, "analysis": result.data,
                               "functions_indexed": count, "functions_truncated": truncated,
                               "methods_indexed": len(methods.data.get("methods", [])),
                               "metadata_status": methods.status})
        if name == "get_dispatch_candidates":
            backend = self._backend(args["image_id"])
            if isinstance(backend, ToolResult):
                return backend
            if not args["selector"] or len(args["selector"]) > 1000:
                raise ValueError("selector must contain 1–1000 characters")
            return self._query(backend, "dispatch_candidates", selector=args["selector"], limit=40)
        entity = self.workspace.entity(self.project_id, args["entity_id"])
        if name == "read_resource":
            if entity.kind not in ("resource", "string", "selector", "class", "class_name"):
                raise ValueError("Entity is not a readable resource or string")
            return ToolResult("ok", {"entity": entity.to_dict(), "observation_only": True})
        if entity.image_id is None or entity.address is None:
            return ToolResult("unsupported", {"entity": entity.to_dict()},
                              error={"code": "no_code_address", "message": "This entity has no native address"})
        backend = self._backend(entity.image_id)
        if isinstance(backend, ToolResult):
            return backend
        operation = {"get_function": "functions", "get_xrefs": "xrefs", "get_calls": "calls",
                     "decompile": "decompile", "get_dispatch_candidates": "dispatch_candidates"}[name]
        params: dict[str, Any] = {"address": entity.address, "limit": 40}
        if operation == "xrefs":
            direction = args.get("direction", "to")
            if direction not in ("to", "from", "both"):
                raise ValueError("direction must be to, from, or both")
            params["direction"] = direction
        result = self._query(backend, operation, **params)
        self._ingest(entity.image_id, result.data)
        result.data.setdefault("image_id", entity.image_id)
        result.data.setdefault("requested_entity", entity.to_dict())
        return result

    def _query(self, backend, operation: str, **params) -> ToolResult:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return ToolResult("timeout", error={"code": "investigation_timeout", "message": "Overall investigation deadline reached"})
        backend.timeout = min(self.timeout, remaining)
        return backend.query(operation, **params)

    def _backend(self, image_id: str):
        if image_id in self.backends:
            return self.backends[image_id]
        image = self.workspace.image(self.project_id, image_id)
        if image.encrypted or image.status not in ("ready", "partial", "analyzable"):
            return ToolResult("unsupported", {"image": image.to_dict()},
                              error={"code": "image_unavailable", "message": "Code analysis is restricted for this image"})
        if image.architecture != "arm64":
            return ToolResult("unsupported", {"image": image.to_dict()},
                              error={"code": "unsupported_architecture", "message": "v0.1 code analysis supports arm64"})
        from .backends.ghidra import GhidraBackend

        project = self.workspace.project_path(self.project_id)
        binary = (project / "bundle" / image.path).resolve()
        if not binary.is_relative_to(project / "bundle"):
            raise ValueError("Binary path escapes the imported bundle")
        offset = int(image.details.get("slice_offset", 0))
        size = int(image.details.get("slice_size", binary.stat().st_size))
        if offset or size != binary.stat().st_size:
            thin = project / "analysis" / "inputs" / image.id
            thin.parent.mkdir(parents=True, exist_ok=True)
            if not thin.exists():
                with binary.open("rb") as source:
                    source.seek(offset)
                    content = source.read(size)
                if len(content) != size:
                    raise ValueError("Truncated Mach-O slice")
                thin.write_bytes(content)
            binary = thin
        backend = GhidraBackend(project / "analysis" / image.id, binary, image.id,
                                timeout=self.timeout)
        self.backends[image_id] = backend
        return backend

    def _ingest(self, image_id: str, data: dict) -> None:
        image = self.workspace.image(self.project_id, image_id)
        entities: list[Entity] = []
        for function in data.get("functions", []):
            address = function.get("address")
            if isinstance(address, str):
                address = int(address, 0)
            if not isinstance(address, int):
                continue
            item = dict(function)
            item["source"] = "ghidra"
            item["image_sha256"] = image.sha256
            entities.append(Entity(stable_id("fn", image_id, address), "function",
                                   function.get("name", f"sub_{address:x}"), image_id=image_id,
                                   address=address, path=image.path, metadata=item))
        for method in data.get("methods", []):
            address = method.get("imp", method.get("address"))
            if isinstance(address, str):
                address = int(address, 0)
            if not isinstance(address, int):
                continue
            name = method.get("name") or f"{method.get('class_name', '?')}::{method.get('selector', '?')}"
            entities.append(Entity(stable_id("objc", image_id, address, name), "function", name,
                                   image_id=image_id, address=address, path=image.path,
                                   metadata={**method, "source": "ghidra", "relation": "declared_method"}))
        for reference in data.get("references", data.get("calls", [])):
            for key in ("from_address", "to_address"):
                address = reference.get(key)
                if isinstance(address, str):
                    address = int(address, 0)
                if isinstance(address, int):
                    eid = stable_id("addr", image_id, address)
                    reference[key + "_entity_id"] = eid
                    entities.append(Entity(eid, "address", f"address_{address:x}", image_id=image_id,
                                           address=address, path=image.path,
                                           metadata={"source": "ghidra", "reference_kind": reference.get("kind")}))
        self.workspace.add_entities(self.project_id, entities)

    def close(self) -> None:
        for backend in self.backends.values():
            backend.close()


def offline_investigate(question: str, toolbox: Toolbox) -> dict:
    """Collect literal observations without impersonating a semantic model."""
    inventory = toolbox.call("list_images", {})
    hits = toolbox.call("search_entities", {"query": question, "limit": 20})
    matches = hits.data.get("matches", [])
    claims = [{"kind": "observation", "text": f"Indexed {item['kind']}: {item['name']}",
               "evidence_ids": hits.evidence_ids} for item in matches[:10]]
    return {"status": "partial", "summary": "Offline evidence collection; no AI implementation explanation was generated.",
            "question": question, "claims": claims,
            "limitations": ["Literal search only. A matching name/string does not prove feature behavior.",
                            "Configure a model endpoint to perform a guided investigation."],
            "evidence_ids": inventory.evidence_ids + hits.evidence_ids, "tool_calls": 2,
            "usage": {}, "messages": []}
