import json
import time

import pytest
from jsonschema import Draft202012Validator
from test_importer import write_ipa

from aire.models import ToolResult
from aire.service import AnalysisService


@pytest.fixture
def service(tmp_path, monkeypatch):
    # External-agent operation must not consult model configuration or credentials.
    monkeypatch.setenv("AIRE_BASE_URL", "not-a-valid-provider-url")
    monkeypatch.setenv("AIRE_MODEL", "unused")
    monkeypatch.setenv("AIRE_API_KEY", "should-never-be-persisted")
    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa)
    instance = AnalysisService(tmp_path / "work", tool_timeout=60)
    imported = instance.call("import_ipa", {"ipa_path": str(ipa)})
    assert imported.status == "ok"
    project_id = imported.data["project"]["id"]
    case = instance.call("start_investigation", {"project_id": project_id, "question": "How do favorites work?"})
    yield instance, project_id, case.data["case_id"]
    instance.close()


def test_tool_contracts_and_validation_are_portable(service):
    instance, _, case_id = service
    names = []
    for spec in instance.tool_specs():
        Draft202012Validator.check_schema(spec["inputSchema"])
        names.append(spec["name"])
    assert len(names) == len(set(names))
    assert instance.call("unknown", {}).error["code"] == "unknown_tool"
    assert instance.call("search_entities", {"case_id": case_id, "query": "favorite", "limit": True}).error["code"] == "invalid_arguments"
    assert instance.call("export_report", {"case_id": case_id, "format": "html", "output": "/outside"}).error["code"] == "invalid_arguments"


def test_model_free_case_findings_evidence_and_exports(service):
    instance, project_id, case_id = service
    result = instance.call("search_entities", {"case_id": case_id, "query": "favorites"})
    assert result.status == "ok" and result.data["matches"]
    eid = result.evidence_ids[0]
    fetched = instance.call("get_evidence", {"case_id": case_id, "evidence_id": eid})
    assert fetched.data["evidence"]["provenance"]["input_sha256"]
    saved = instance.call("save_findings", {
        "case_id": case_id, "summary": "UNSUPPORTED FREE-FORM SUMMARY",
        "claims": [{"text": "The index contains a favorites-related string.",
                    "kind": "observation", "evidence_ids": [eid]}],
        "limitations": ["A string alone does not establish implementation."]})
    assert saved.status == "ok"
    assert "UNSUPPORTED" not in saved.data["report"]["summary"]
    assert saved.data["report"]["summary_source"] == "first_three_cited_claims"
    assert "Summary rebuilt" in saved.data["note"]
    exported = instance.call("export_report", {"case_id": case_id, "format": "json"})
    packet = json.loads(instance.workspace.root.joinpath("reports", case_id + ".json").read_text())
    assert exported.status == "ok"
    assert packet["project"]["id"] == project_id
    assert packet["evidence"][0]["id"] == eid
    assert "should-never-be-persisted" not in json.dumps(packet)
    assert not packet["report"]["validation"]["semantic_correctness_verified"]


def test_cross_case_evidence_is_rejected_and_claims_demoted(service):
    instance, project_id, first = service
    hit = instance.call("search_entities", {"case_id": first, "query": "favorites"})
    eid = hit.evidence_ids[0]
    second = instance.call("start_investigation", {"project_id": project_id, "question": "another feature"}).data["case_id"]
    assert instance.call("get_evidence", {"case_id": second, "evidence_id": eid}).status == "error"
    saved = instance.call("save_findings", {
        "case_id": second, "summary": "Uses SQLite", "limitations": [],
        "claims": [{"kind": "observation", "text": "Uses SQLite", "evidence_ids": [eid]}]})
    assert saved.status == "partial"
    assert saved.data["report"]["claims"][0]["kind"] == "unknown"
    assert saved.data["report"]["summary"] != "Uses SQLite"


def test_case_getter_does_not_expose_standalone_conversation(service):
    instance, _, case_id = service
    instance.workspace.save_case(case_id, {"status": "complete", "claims": [],
                                          "messages": [{"role": "user", "content": "private conversation"}]})
    result = instance.call("get_investigation", {"case_id": case_id})
    assert "private conversation" not in json.dumps(result.to_dict())


def test_external_calls_refresh_deadlines_and_evict_workers_without_losing_cases(service):
    instance, project_id, first = service
    box = instance._box(first)
    box.deadline = 0
    image = next(i for i in instance.workspace.images(project_id) if not i.encrypted)

    class Backend:
        closed = False

        def query(self, operation, **params):
            assert self.timeout > 0
            return ToolResult("partial", {"candidates": [], "receiver_resolved": False})

        def close(self):
            self.closed = True

    backend = Backend()
    box.backends[image.id] = backend
    result = instance.call("get_dispatch_candidates", {"case_id": first, "image_id": image.id, "selector": "saveFavorite:"})
    assert result.status == "partial"
    assert box.deadline > time.monotonic()
    for question in ("second", "third"):
        case_id = instance.call("start_investigation", {"project_id": project_id, "question": question}).data["case_id"]
        instance.call("list_images", {"case_id": case_id})
    assert backend.closed
    assert first not in instance._boxes
    assert instance.call("get_investigation", {"case_id": first}).data["evidence_ids"]


def test_running_case_cannot_export_an_unsubmitted_answer(service):
    instance, _, case_id = service
    assert instance.call("export_report", {"case_id": case_id}).status == "error"
    saved = instance.call("save_findings", {"case_id": case_id, "summary": "I know the answer",
                                           "claims": [], "limitations": ["No evidence yet"]})
    assert saved.status == "partial"
    assert instance.call("export_report", {"case_id": case_id}).status == "ok"
