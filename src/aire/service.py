"""Local analysis workflows for external agents; no model client is used here."""

from __future__ import annotations

import copy
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .models import ToolResult
from .report import export_case, validate_report
from .tools import Toolbox
from .workspace import Workspace


def _tool(name: str, description: str, properties: dict, required: list[str],
          *, read_only: bool = True, idempotent: bool = True) -> dict:
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties,
                            "required": required, "additionalProperties": False},
            "annotations": {"readOnlyHint": read_only, "destructiveHint": False,
                            "idempotentHint": idempotent, "openWorldHint": False}}


class AnalysisService:
    """Own one workspace and a bounded set of reusable native workers.

    Construct, call, and close on the same thread. The MCP adapter serializes calls.
    External agents own reasoning and conversation; only tool evidence and explicitly
    submitted findings are persisted here.
    """

    def __init__(self, workspace_root: Path, tool_timeout: float = 180):
        if not 1 <= tool_timeout <= 3600:
            raise ValueError("Tool timeout must be between 1 and 3600 seconds")
        self.workspace = Workspace(workspace_root)
        self.tool_timeout = tool_timeout
        self._boxes: OrderedDict[str, Toolbox] = OrderedDict()
        self._specs = {item["name"]: item for item in self.tool_specs()}
        self._validators = {name: Draft202012Validator(item["inputSchema"])
                            for name, item in self._specs.items()}

    @staticmethod
    def tool_specs() -> list[dict]:
        identifier = {"type": "string", "minLength": 1, "maxLength": 120,
                      "pattern": "^[A-Za-z0-9_-]+$"}
        project = {"project_id": identifier}
        case = {"case_id": identifier}
        limit = {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}
        claim = {"type": "object", "properties": {
            "text": {"type": "string", "minLength": 1, "maxLength": 8000},
            "kind": {"type": "string", "enum": ["observation", "inference", "unknown"]},
            "evidence_ids": {"type": "array", "items": identifier, "maxItems": 30}},
            "required": ["text", "kind", "evidence_ids"], "additionalProperties": False}
        specs = [
            _tool("import_ipa", "Import a user-supplied local IPA without running it. "
                  "Copies extracted content into this server's workspace, indexes readable facts, "
                  "and reports encryption/architecture limits. Does not upload the IPA.",
                  {"ipa_path": {"type": "string", "minLength": 1, "maxLength": 4096}},
                  ["ipa_path"], read_only=False),
            _tool("list_projects", "List already imported local projects (newest first).",
                  {"limit": limit}, []),
            _tool("inspect_project", "Read a package manifest, image identities and capability limits.",
                  project, ["project_id"]),
            _tool("start_investigation", "Create a local evidence case for one feature question. "
                  "The external agent performs the reasoning; no model API is called by aire.",
                  {**project, "question": {"type": "string", "minLength": 1, "maxLength": 8000}},
                  ["project_id", "question"], read_only=False, idempotent=False),
            _tool("get_investigation", "Read a saved case, submitted findings and evidence IDs. "
                  "Submitted findings are agent-authored interpretations, not independent observations.",
                  case, ["case_id"]),
            _tool("list_cases", "List saved investigations for one imported project.",
                  {**project, "limit": limit}, ["project_id"]),
            _tool("get_evidence", "Read a saved tool result with its parameters, output digest "
                  "and provenance. Evidence must belong to this case.",
                  {**case, "evidence_id": identifier}, ["case_id", "evidence_id"]),
            _tool("save_findings", "Save the external agent's findings. Factual claims require "
                  "evidence from this case. Invalid/unsuccessful references become unknown. "
                  "The saved summary is rebuilt from the first three cited claims; put the "
                  "implementation overview first. This validates provenance identifiers, "
                  "not semantic correctness.",
                  {**case, "summary": {"type": "string", "maxLength": 16000},
                   "claims": {"type": "array", "items": claim, "maxItems": 100},
                   "limitations": {"type": "array", "items": {"type": "string", "maxLength": 4000},
                                   "maxItems": 50}},
                  ["case_id", "summary", "claims", "limitations"], read_only=False),
            _tool("export_report", "Export saved findings and raw evidence to this workspace's "
                  "reports directory. Does not generate a model answer or publish anything.",
                  {**case, "format": {"type": "string", "enum": ["html", "md", "json"],
                                      "default": "html"}}, ["case_id"], read_only=False),
        ]
        for original in Toolbox.specs():
            item = original["function"]
            schema = copy.deepcopy(item["parameters"])
            schema["properties"] = {**case, **schema["properties"]}
            schema["required"] = ["case_id", *schema["required"]]
            specs.append({"name": item["name"], "description": item["description"] +
                          " Tool evidence is persisted in the specified case.",
                          "inputSchema": schema,
                          "annotations": {"readOnlyHint": item["name"] != "analyze_image",
                                          "destructiveHint": False, "idempotentHint": True,
                                          "openWorldHint": False}})
        return specs

    def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        validator = self._validators.get(name)
        if validator is None:
            return ToolResult("error", error={"code": "unknown_tool", "message": "Unknown aire tool"})
        # Do not echo rejected input: it can contain unrelated local secrets.
        if not isinstance(arguments, dict) or not validator.is_valid(arguments):
            return ToolResult("error", error={"code": "invalid_arguments",
                                              "message": f"Arguments do not match {name}'s input schema"})
        try:
            return self._call(name, arguments)
        except (ValueError, OSError, KeyError, TypeError) as exc:
            return ToolResult("error", error={"code": "workflow_error", "message": str(exc)[:1000]})

    def _box(self, case_id: str) -> Toolbox:
        case = self.workspace.case(case_id)
        if case_id not in self._boxes:
            while len(self._boxes) >= 2:
                _, oldest = self._boxes.popitem(last=False)
                oldest.close()
            self._boxes[case_id] = Toolbox(self.workspace, case["project_id"], case_id,
                                           timeout=self.tool_timeout)
        self._boxes.move_to_end(case_id)
        box = self._boxes[case_id]
        # A host agent may think for minutes between calls. The budget is per tool,
        # not measured from MCP session creation.
        box.deadline = time.monotonic() + self.tool_timeout
        return box

    def _call(self, name: str, args: dict) -> ToolResult:
        w = self.workspace
        if name == "import_ipa":
            project = w.import_ipa(Path(args["ipa_path"]))
            return ToolResult("ok", {"project": project,
                                      "next_step": "start_investigation with the project id and feature question"})
        if name == "list_projects":
            projects = w.projects()
            maximum = args.get("limit", 20)
            return ToolResult("partial" if len(projects) > maximum else "ok",
                              {"projects": [{"id": p["id"], "app_name": p["app_name"],
                                             "bundle_id": p["bundle_id"],
                                             "input_sha256": p["input_sha256"]}
                                            for p in projects[:maximum]],
                               "total": len(projects), "truncated": len(projects) > maximum})
        if name == "inspect_project":
            return ToolResult("ok", {"project": w.project(args["project_id"])})
        if name == "start_investigation":
            if not args["question"].strip():
                raise ValueError("Question must not be blank")
            case_id = w.new_case(args["project_id"], args["question"])
            w.save_case(case_id, {"status": "running", "summary": "External-agent investigation in progress.",
                                  "question": args["question"], "claims": [], "limitations": [],
                                  "mode": "external_agent", "messages": []})
            return ToolResult("ok", {"case_id": case_id, "project_id": args["project_id"],
                                      "question": args["question"], "mode": "external_agent",
                                      "note": "Use case_id for analysis tools; save_findings then export_report."})
        if name == "list_cases":
            w.project(args["project_id"])
            limit = args.get("limit", 20)
            rows = w.db.execute("SELECT id,question,status,updated_at FROM cases WHERE project_id=? "
                                "ORDER BY updated_at DESC LIMIT ?", (args["project_id"], limit + 1)).fetchall()
            return ToolResult("partial" if len(rows) > limit else "ok",
                              {"cases": [dict(r) for r in rows[:limit]], "truncated": len(rows) > limit})
        if name == "get_investigation":
            case = w.case(args["case_id"])
            case.pop("messages", None)
            evidence = w.evidence_for_case(case["id"])
            return ToolResult("ok", {"case": case, "evidence_ids": [e["id"] for e in evidence],
                                      "findings_origin": "agent_authored",
                                      "semantic_correctness_verified": False})
        if name == "get_evidence":
            case_id, eid = args["case_id"], args["evidence_id"]
            w.case(case_id)
            if not w.db.execute("SELECT 1 FROM case_evidence WHERE case_id=? AND evidence_id=?",
                                (case_id, eid)).fetchone():
                raise ValueError("Evidence does not belong to this investigation")
            return ToolResult("ok", {"evidence": w.evidence(eid)}, evidence_ids=[eid])
        if name == "save_findings":
            case_id = args["case_id"]
            case = w.case(case_id)
            report = {"question": case["question"], "summary": args["summary"],
                      "claims": args["claims"], "limitations": args["limitations"],
                      "status": "complete", "mode": "external_agent",
                      "findings_origin": "agent_authored", "messages": case["messages"]}
            report = validate_report(report, w.evidence_for_case(case_id))
            if not report["claims"] or any(c["kind"] == "unknown" for c in report["claims"]):
                report["status"] = "partial"
            # The host-supplied prose summary must not bypass claim validation.
            supported = [c["text"] for c in report["claims"] if c["kind"] != "unknown"]
            report["summary"] = " ".join(supported[:3]) if supported else "Insufficient cited evidence; review the unresolved findings."
            report["summary_source"] = "first_three_cited_claims"
            w.save_case(case_id, report)
            return ToolResult(report["status"] if report["status"] == "partial" else "ok",
                              {"case_id": case_id, "report": {k: v for k, v in report.items() if k != "messages"},
                               "note": "Summary rebuilt from the first three claims that passed citation checks; "
                                       "review claim order and the saved summary. Semantic correctness is not verified.",
                               "semantic_correctness_verified": False})
        if name == "export_report":
            case = w.case(args["case_id"])
            if case["status"] == "running":
                raise ValueError("Save findings before exporting this investigation")
            path = export_case(w, args["case_id"], args.get("format", "html"))
            return ToolResult("ok", {"case_id": args["case_id"], "path": str(path),
                                      "format": args.get("format", "html"),
                                      "published": False})
        arguments = {k: v for k, v in args.items() if k != "case_id"}
        box = self._box(args["case_id"])
        try:
            return box.call(name, arguments)
        finally:
            # Retain one native worker per active case; analysis databases stay cached.
            while len(box.backends) > 1:
                first = next(iter(box.backends))
                box.backends.pop(first).close()

    def close(self) -> None:
        for box in self._boxes.values():
            box.close()
        self._boxes.clear()
        self.workspace.close()
