import pytest
from test_importer import write_ipa

from aire.models import ToolResult
from aire.workspace import Workspace


@pytest.fixture
def imported(tmp_path):
    ipa = tmp_path / "example.ipa"
    write_ipa(ipa)
    store = Workspace(tmp_path / "workspace")
    project = store.import_ipa(ipa)
    yield store, project, ipa
    store.close()


def test_import_is_idempotent_and_searches_short_chinese(imported):
    store, project, ipa = imported
    assert store.import_ipa(ipa)["id"] == project["id"]
    assert len(store.projects()) == 1
    assert "收藏" in store.search(project["id"], "收藏")[0]["value"]
    assert store.search(project["id"], "favorites")[0]["kind"] in ("resource", "string", "symbol")
    assert store.search(project["id"], '" OR * --') is not None


def test_identical_frameworks_in_different_packages_remain_scoped(imported, tmp_path):
    store, first, _ = imported
    ipa = tmp_path / "second.ipa"
    write_ipa(ipa, {"Payload/Example.app/config.json": b'{"database":"different.sqlite"}'})
    second = store.import_ipa(ipa)
    assert first["id"] != second["id"]
    assert store.search(first["id"], "favorites.sqlite")
    assert not store.search(first["id"], "different")
    assert store.search(second["id"], "different.sqlite")
    a = store.search(first["id"], "收藏")[0]
    b = store.search(second["id"], "收藏")[0]
    assert a["id"] != b["id"]


def test_evidence_roundtrips_and_delete_removes_related_data(imported):
    store, project, ipa = imported
    cid = store.new_case(project["id"], "收藏怎么实现")
    result = ToolResult("ok", {"address": 123, "text": "收藏"})
    eid = store.record_evidence(project["id"], cid, "test", {"a": 1}, result)
    assert store.record_evidence(project["id"], cid, "test", {"a": 1}, result) == eid
    record = store.evidence(eid)
    assert len(record["digest"]) == 64
    assert record["result"]["data"]["text"] == "收藏"
    report = {"summary": "partial", "status": "partial", "messages": [{"role": "user", "content": "hello"}]}
    store.save_case(cid, report)
    assert "messages" in report
    assert store.case(cid)["messages"] == report["messages"]
    reports = store.root / "reports"
    reports.mkdir()
    (reports / f"{cid}.html").write_text("saved report")
    store.delete_project(project["id"])
    assert ipa.exists()
    assert not (reports / f"{cid}.html").exists()
    assert not store.projects()
    with pytest.raises(ValueError):
        store.evidence(eid)


def test_unsafe_import_rolls_back_all_project_state(tmp_path):
    ipa = tmp_path / "bad.ipa"
    write_ipa(ipa, {"../escape": b"bad"})
    store = Workspace(tmp_path / "workspace")
    with pytest.raises(ValueError):
        store.import_ipa(ipa)
    assert store.projects() == []
    assert not (tmp_path / "escape").exists()
    store.close()
