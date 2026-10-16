"""Interoperability checks against the actual stdio MCP process."""

import asyncio
import json
import sys
import textwrap
from datetime import timedelta
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from test_importer import write_ipa

from aire.mcp_server import MAX_RESULT_BYTES

ROOT = Path(__file__).resolve().parents[1]


def _parameters(workspace, *, script=None):
    args = (
        ["-c", script, str(workspace)]
        if script
        else ["-m", "aire", "--workspace", str(workspace), "mcp"]
    )
    return StdioServerParameters(
        command=sys.executable,
        args=args,
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
    )


def _payload(result):
    assert result.structuredContent is not None
    assert len(result.content) == 1
    assert result.content[0].type == "text"
    payload = json.loads(result.content[0].text)
    assert payload == result.structuredContent
    assert {"status", "data", "evidence_ids", "error"} <= payload.keys()
    return payload


def test_actual_stdio_import_investigate_evidence_finalize_and_export(tmp_path):
    ipa = tmp_path / "Example.ipa"
    write_ipa(ipa)
    workspace = tmp_path / "work"

    async def workflow():
        with (tmp_path / "stderr.log").open("w+") as log:
            async with (
                stdio_client(_parameters(workspace), errlog=log) as (read, write),
                ClientSession(read, write, read_timeout_seconds=timedelta(seconds=30)) as session,
            ):
                initialized = await session.initialize()
                assert initialized.serverInfo.name == "aire"
                assert initialized.capabilities.tools is not None
                assert getattr(initialized.capabilities, "sampling", None) is None
                await session.send_ping()
                tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                assert {
                    "import_ipa",
                    "start_investigation",
                    "search_entities",
                    "get_evidence",
                    "save_findings",
                    "export_report",
                } <= tools.keys()
                assert "case_id" in tools["search_entities"].inputSchema["required"]

                imported = _payload(await session.call_tool("import_ipa", {"ipa_path": str(ipa)}))
                assert imported["status"] == "ok"
                project = imported["data"].get("project", imported["data"])
                pid = project.get("project_id", project.get("id"))
                assert pid
                started = _payload(
                    await session.call_tool(
                        "start_investigation",
                        {
                            "project_id": pid,
                            "question": "Which bookmark storage strings are indexed?",
                        },
                    )
                )
                assert started["status"] == "ok"
                case = started["data"].get("case", started["data"])
                cid = case.get("case_id", case.get("id"))
                assert cid
                found = _payload(
                    await session.call_tool(
                        "search_entities", {"case_id": cid, "query": "favorites", "limit": 5}
                    )
                )
                assert found["status"] == "ok"
                assert found["data"]["matches"]
                eid = found["evidence_ids"][0]
                observed = _payload(
                    await session.call_tool("get_evidence", {"case_id": cid, "evidence_id": eid})
                )
                assert observed["status"] == "ok"
                assert eid in json.dumps(observed["data"])

                finalized = _payload(
                    await session.call_tool(
                        "save_findings",
                        {
                            "case_id": cid,
                            "summary": "The IPA index contains a favorites-related storage string.",
                            "claims": [
                                {
                                    "kind": "observation",
                                    "text": "The index contains a favorites-related storage string.",
                                    "evidence_ids": [eid],
                                }
                            ],
                            "limitations": ["A matching string does not prove feature behavior."],
                        },
                    )
                )
                assert finalized["status"] == "ok"
                saved = _payload(await session.call_tool("get_investigation", {"case_id": cid}))
                assert eid in json.dumps(saved["data"])
                exported = _payload(
                    await session.call_tool("export_report", {"case_id": cid, "format": "json"})
                )
                assert exported["status"] == "ok"
                paths = list((workspace / "reports").glob("*.json"))
                assert len(paths) == 1
                packet = json.loads(paths[0].read_text())
                assert packet["report"]["claims"][0]["evidence_ids"] == [eid]
                assert packet["report"]["validation"]["citations_checked"]
                assert not packet["report"]["validation"]["semantic_correctness_verified"]
                assert packet["evidence"]

    asyncio.run(workflow())


FAULT_SERVICE = textwrap.dedent("""
    import os
    import sys
    import threading
    import types
    from pathlib import Path
    from aire.models import ToolResult

    class FaultService:
        def __init__(self, root, tool_timeout=180):
            self.root = root
            self.root.mkdir(parents=True, exist_ok=True)
            self.owner = threading.get_ident()
            print("service constructor noise", flush=True)

        def check_thread(self):
            assert self.owner == threading.get_ident(), "service crossed threads"

        def tool_specs(self):
            self.check_thread()
            return [{"name": "probe", "description": "Transport fault fixture",
                     "inputSchema": {"type": "object", "properties": {"mode": {"type": "string"}},
                                     "required": ["mode"], "additionalProperties": False}}]

        def call(self, name, arguments):
            self.check_thread()
            print("service call noise", flush=True)
            os.write(1, b"native service noise\\n")
            mode = arguments["mode"]
            if mode == "raise":
                raise RuntimeError("fixture internal failure")
            if mode == "large":
                return ToolResult("ok", {"pseudocode": "汉字" * 100000}, ["ev_keep"])
            if mode == "many_ids":
                return ToolResult("ok", {}, ["ev_" + str(i) * 10 for i in range(10000)])
            return ToolResult(mode, {"thread": self.owner}, ["ev_keep"],
                              {"code": mode, "message": "fixture status"} if mode != "ok" else None)

        def close(self):
            self.check_thread()
            (self.root / "closed").write_text(str(self.owner))
            print("service close noise", flush=True)

    module = types.ModuleType("aire.service")
    module.AnalysisService = FaultService
    sys.modules["aire.service"] = module
    from aire.mcp_server import serve
    serve(Path(sys.argv[1]))
""")


def test_stdio_statuses_argument_errors_stdout_isolation_and_eof_cleanup(tmp_path):
    workspace = tmp_path / "fault"
    threads = set()

    async def workflow():
        with (tmp_path / "stderr.log").open("w+") as log:
            async with (
                stdio_client(_parameters(workspace, script=FAULT_SERVICE), errlog=log) as (
                    read,
                    write,
                ),
                ClientSession(read, write, read_timeout_seconds=timedelta(seconds=20)) as session,
            ):
                await session.initialize()
                assert [tool.name for tool in (await session.list_tools()).tools] == ["probe"]
                await session.send_ping()
                for status in ("ok", "partial", "unsupported", "timeout", "error"):
                    response = await session.call_tool("probe", {"mode": status})
                    payload = _payload(response)
                    assert payload["status"] == status
                    assert response.isError is (status in {"unsupported", "timeout", "error"})
                    assert payload["evidence_ids"] == ["ev_keep"]
                    threads.add(payload["data"]["thread"])
                for arguments in ({}, {"mode": 7}, {"mode": "ok", "extra": True}):
                    response = await session.call_tool("probe", arguments)
                    assert response.isError
                    assert _payload(response)["error"]["code"] == "invalid_arguments"
                with pytest.raises(McpError) as unknown:
                    await session.call_tool("missing_tool", {})
                assert unknown.value.error.code == -32602
                failed = await session.call_tool("probe", {"mode": "raise"})
                assert failed.isError
                assert _payload(failed)["error"]["code"] == "internal_error"
                # An ordinary call and ping still work after a failed call.
                await session.call_tool("probe", {"mode": "ok"})
                await session.send_ping()
            log.flush()
            log.seek(0)
            stderr = log.read()
            assert "service constructor noise" in stderr
            assert "service call noise" in stderr
            assert "native service noise" in stderr
            assert "service close noise" in stderr
            assert "fixture internal failure" in stderr

    asyncio.run(workflow())
    assert len(threads) == 1
    assert (workspace / "closed").read_text() == str(next(iter(threads)))


def test_stdio_large_responses_are_valid_bounded_json_with_provenance(tmp_path):
    async def workflow():
        with (tmp_path / "stderr.log").open("w") as log:
            async with (
                stdio_client(_parameters(tmp_path / "fault", script=FAULT_SERVICE), errlog=log) as (
                    read,
                    write,
                ),
                ClientSession(read, write, read_timeout_seconds=timedelta(seconds=20)) as session,
            ):
                await session.initialize()
                response = await session.call_tool("probe", {"mode": "large"})
                payload = _payload(response)
                assert not response.isError
                assert payload["status"] == "partial"
                assert payload["evidence_ids"] == ["ev_keep"]
                truncation = payload["data"]["transport_truncation"]
                assert truncation["truncated"]
                assert truncation["original_status"] == "ok"
                assert truncation["original_json_bytes"] > MAX_RESULT_BYTES
                assert len(response.content[0].text.encode("utf-8")) <= MAX_RESULT_BYTES
                many = await session.call_tool("probe", {"mode": "many_ids"})
                payload = _payload(many)
                truncation = payload["data"]["transport_truncation"]
                assert truncation["evidence_ids_returned"] < truncation["evidence_ids_total"]
                assert payload["evidence_ids"][0] == "ev_" + "0" * 10
                assert len(many.content[0].text.encode("utf-8")) <= MAX_RESULT_BYTES

    asyncio.run(workflow())
