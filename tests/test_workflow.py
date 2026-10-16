import json

from test_importer import write_ipa
from typer.testing import CliRunner

from aire.cli import app
from aire.models import ToolResult
from aire.report import export_case, validate_report
from aire.tools import Toolbox
from aire.workspace import Workspace


def test_cli_import_search_investigate_export_and_replay(tmp_path):
    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa)
    runner = CliRunner()
    base = ["--workspace", str(tmp_path / "work")]
    result = runner.invoke(app, [*base, "import", str(ipa), "--json"])
    assert result.exit_code == 0, result.output
    pid = json.loads(result.stdout)["id"]
    search = runner.invoke(app, [*base, "search", pid, "收藏"])
    assert search.exit_code == 0
    assert "收藏" in search.stdout
    result = runner.invoke(app, [*base, "ask", pid, "收藏", "--offline"])
    assert result.exit_code == 0, result.output
    store = Workspace(tmp_path / "work")
    cid = store.db.execute("SELECT id FROM cases").fetchone()[0]
    saved = store.case(cid)
    assert saved["status"] == "partial"
    assert "no AI" in saved["report"]["summary"]
    eid = store.evidence_for_case(cid)[0]["id"]
    packet = export_case(store, cid, "json")
    assert json.loads(packet.read_text())["evidence"]
    store.close()
    replay = runner.invoke(app, [*base, "replay", eid])
    assert replay.exit_code == 0, replay.output
    assert json.loads(replay.stdout)["matches"] is True


def test_encrypted_code_is_blocked_before_backend_instantiation(tmp_path, monkeypatch):
    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa)
    store = Workspace(tmp_path / "work")
    project = store.import_ipa(ipa)
    cid = store.new_case(project["id"], "feature")
    tools = Toolbox(store, project["id"], cid)
    image = next(i for i in store.images(project["id"]) if i.encrypted)
    result = tools.call("analyze_image", {"image_id": image.id})
    assert result.status == "unsupported"
    assert result.error["code"] == "image_unavailable"
    assert tools.evidence_ids
    store.close()


def test_html_escapes_untrusted_strings_and_claims(tmp_path):
    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa)
    store = Workspace(tmp_path / "work")
    project = store.import_ipa(ipa)
    cid = store.new_case(project["id"], "<script>alert('question')</script>")
    ev = store.record_evidence(project["id"], cid, "search", {}, ToolResult("ok", {"s": "<script>alert('ipa')</script>"}))
    store.save_case(cid, {"status": "complete", "summary": "<img src=x onerror=alert(1)>",
                          "claims": [{"kind": "observation", "text": "<script>claim</script>", "evidence_ids": [ev]}]})
    page = export_case(store, cid).read_text()
    assert "<script>" not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;" in page
    assert "Content-Security-Policy" in page
    store.close()


def test_invented_or_failed_evidence_cannot_support_factual_claims():
    report = {"summary": "UNSUPPORTED FACT", "claims": [{"text": "Works", "kind": "observation", "evidence_ids": ["fake"]},
                         {"text": "Works too", "kind": "inference", "evidence_ids": ["ev1"]}]}
    validated = validate_report(report, [{"id": "ev1", "result": {"status": "unsupported"}}])
    assert all(c["kind"] == "unknown" for c in validated["claims"])
    assert validated["status"] == "partial"
    assert "UNSUPPORTED FACT" not in validated["summary"]
    assert not validated["validation"]["semantic_correctness_verified"]


def test_no_model_configuration_never_uses_a_default_cloud(tmp_path, monkeypatch):
    for key in ("AIRE_MODEL", "AIRE_BASE_URL", "AIRE_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa)
    store = Workspace(tmp_path / "work")
    pid = store.import_ipa(ipa)["id"]
    store.close()
    result = CliRunner().invoke(app, ["--workspace", str(tmp_path / "work"), "ask", pid, "feature"])
    assert result.exit_code == 1
    assert "AIRE_BASE_URL" in result.stdout


def test_version_is_available_without_a_subcommand():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "0.1.0"


def test_selector_lookup_forwards_selector_and_overall_deadline(tmp_path):
    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa)
    store = Workspace(tmp_path / "work")
    project = store.import_ipa(ipa)
    cid = store.new_case(project["id"], "selector")
    box = Toolbox(store, project["id"], cid)
    image = next(i for i in store.images(project["id"]) if not i.encrypted)

    class Backend:
        def query(self, operation, **params):
            assert operation == "dispatch_candidates"
            assert params["selector"] == "saveFavorite:"
            return ToolResult("partial", {"receiver_resolved": False, "candidates": ["a", "b"]})

        def close(self):
            pass

    box.backends[image.id] = Backend()
    result = box.call("get_dispatch_candidates", {"image_id": image.id, "selector": "saveFavorite:"})
    assert result.status == "partial"
    assert not result.data["receiver_resolved"]
    box.deadline = 0
    result = box.call("get_dispatch_candidates", {"image_id": image.id, "selector": "saveFavorite:"})
    assert result.status == "timeout"
    store.close()


def test_markdown_prose_cannot_inject_external_media(tmp_path):
    from aire.report import render_markdown

    page = render_markdown({"question": "![external](https://example.org/image.png)",
                           "project": {"input_sha256": "a" * 64},
                           "report": {"summary": '<img src="https://example.org/image.png">',
                                      "claims": [], "limitations": []}, "evidence": []})
    assert "![external](" not in page
    assert "<img" not in page
    assert "&lt;img" in page


def test_scripted_provider_investigates_with_real_toolbox_and_saved_evidence(tmp_path):
    from aire.agent import Investigator
    from aire.providers import ModelConfig

    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa)
    store = Workspace(tmp_path / "work")
    project = store.import_ipa(ipa)
    cid = store.new_case(project["id"], "Which storage strings are present?")
    box = Toolbox(store, project["id"], cid)

    class ScriptedProvider:
        count = 0

        def complete(self, messages, tools, **kwargs):
            self.count += 1
            if self.count == 1:
                message = {"content": None, "tool_calls": [{"id": "search1", "type": "function",
                    "function": {"name": "search_entities", "arguments": '{"query":"favorites"}'}}]}
            else:
                result = json.loads(messages[-1]["content"])
                assert result["data"]["matches"]
                message = {"content": json.dumps({"summary": "The index contains a favorites-related storage string.", "claims": [{"kind": "observation",
                    "text": "The index contains a favorites-related storage string.",
                    "evidence_ids": result["evidence_ids"]}],
                    "limitations": ["A string does not prove feature behavior."]})}
            return {"choices": [{"message": message}], "usage": {"total_tokens": 100}}

    agent = Investigator(ModelConfig("http://localhost:1234/v1", "scripted-test"))
    agent.provider = ScriptedProvider()
    result = agent.run("Which storage strings are present?", box)
    assert result["status"] == "complete"
    assert result["claims"][0]["evidence_ids"][0] in box.evidence_ids
    store.save_case(cid, result)
    assert export_case(store, cid).exists()
    store.close()
