"""Protocol/lifecycle tests. These do not stand in for Ghidra integration tests."""

import subprocess
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aire.backends.ghidra import GhidraBackend
from aire.backends.ghidra_worker import Worker, parse_objc_name


@pytest.fixture
def backend(tmp_path):
    binary = tmp_path / "image"
    binary.write_bytes(b"not a real Mach-O: transport fixture only")
    instance = GhidraBackend(tmp_path / "project", binary, "image-test", timeout=1)
    yield instance
    instance.close()


def transport_stub(backend, monkeypatch, behavior="ok"):
    """Use an explicit fake transport process; do not monkeypatch Ghidra exports."""
    monkeypatch.setattr(backend, "_check_environment", lambda: None)
    script = """
import json,sys,time
for line in sys.stdin:
 r=json.loads(line)
 behavior=BEHAVIOR
 if behavior=="timeout": time.sleep(10)
 if behavior=="exit": sys.exit(7)
 if behavior=="bad_json": print("not JSON",flush=True);continue
 d={"schema_version":1,"request_id":r["request_id"],"status":"ok",
    "data":{"image_id":"image-test","operation":r["operation"]}}
 if behavior=="wrong_id":d["request_id"]="wrong"
 if behavior=="wrong_image":d["data"]["image_id"]="other"
 if behavior=="wrong_schema":d["schema_version"]=900
 if behavior=="wrong_status":d["status"]="made_up"
 print(json.dumps(d),flush=True)
""".replace("BEHAVIOR", repr(behavior))

    def start():
        import queue

        backend._responses = queue.Queue()
        backend._process = subprocess.Popen(
            [sys.executable, "-u", "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        output, responses = backend._process.stdout, backend._responses

        def read():
            for line in output:
                responses.put(line)
            responses.put(None)

        threading.Thread(target=read, daemon=True).start()

    monkeypatch.setattr(backend, "_start", start)


def test_missing_environment_is_explicit(backend, monkeypatch):
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    result = backend.query("functions")
    assert result.status == "unsupported"
    assert result.error["code"] == "ghidra_missing"
    assert result.data == {"image_id": "image-test"}
    assert backend._process is None


def test_unknown_operation_does_not_start_worker(backend):
    assert backend.query("arbitrary_shell").status == "unsupported"
    assert backend._process is None


def test_missing_binary(backend):
    backend.binary_path.unlink()
    assert backend.query("analyze").error["code"] == "binary_missing"


def test_success_reuses_worker(backend, monkeypatch):
    transport_stub(backend, monkeypatch)
    first = backend.query("functions", limit=2)
    process = backend._process
    second = backend.query("decompile", address=4096)
    assert first.status == second.status == "ok"
    assert second.data["operation"] == "decompile"
    assert backend._process is process


@pytest.mark.parametrize(
    "behavior", ["bad_json", "wrong_id", "wrong_image", "wrong_schema", "wrong_status"]
)
def test_bad_responses_are_rejected(backend, monkeypatch, behavior):
    transport_stub(backend, monkeypatch, behavior)
    result = backend.query("functions")
    assert result.status == "error"
    assert result.error["code"] == "worker_protocol_error"
    assert backend._process is None


def test_timeout_terminates_worker(backend, monkeypatch):
    backend.timeout = 0.1
    transport_stub(backend, monkeypatch, "timeout")
    result = backend.query("analyze")
    assert result.status == "timeout"
    assert backend._process is None


def test_worker_crash_is_explicit(backend, monkeypatch):
    transport_stub(backend, monkeypatch, "exit")
    result = backend.query("functions")
    assert result.error["code"] == "worker_exited"


def test_nonserializable_request(backend, monkeypatch):
    monkeypatch.setattr(backend, "_check_environment", lambda: None)
    result = backend.query("functions", address=Path("a"))
    assert result.error["code"] == "worker_protocol_error"
    assert backend._process is None


def test_objc_names_preserve_ambiguity():
    assert parse_objc_name("-[First save:]")["selector"] == "save:"
    assert parse_objc_name("-[Second save:]")["selector"] == "save:"
    assert parse_objc_name("+[Store sharedStore]")["method_kind"] == "+"
    assert parse_objc_name("save", "ordinary::Class") is None
    assert parse_objc_name("save:", "Store", {"Store"})["class_name"] == "Store"
    assert parse_objc_name("save:", "Other", {"Store"}) is None


@pytest.mark.parametrize(
    ("kind", "computed", "target_name", "certainty", "dynamic"),
    [
        ("UNCONDITIONAL_CALL", False, "_puts", "observed", False),
        ("CALL_OVERRIDE_UNCONDITIONAL", False, "Store::save:", "candidate", False),
        ("COMPUTED_CALL", True, "Store::save:", "candidate", False),
        ("UNCONDITIONAL_CALL", False, "objc_stub::save:", "observed", True),
    ],
)
def test_reference_certainty(kind, computed, target_name, certainty, dynamic):
    """A Ghidra override is an inference, even if its target has a concrete address."""
    worker = Worker(Path("unused"), Path("unused"), "test")
    worker.program = MagicMock()
    manager = worker.program.getFunctionManager.return_value
    manager.getFunctionContaining.return_value = None
    manager.getFunctionAt.return_value.getName.return_value = target_name
    reference = MagicMock()
    reference.getToAddress.return_value.getOffset.return_value = 4096
    reference.getFromAddress.return_value.getOffset.return_value = 8192
    reference.getToAddress.return_value.getAddressSpace.return_value.getName.return_value = "ram"
    reference.getReferenceType.return_value.__str__.return_value = kind
    reference.getReferenceType.return_value.isComputed.return_value = computed
    data = worker.reference_data(reference)
    assert data["certainty"] == certainty
    assert data["metadata"]["dynamic_dispatch"] is dynamic
    if dynamic:
        assert data["metadata"]["dispatch_selector"] == "save:"


def test_single_selector_match_remains_unresolved():
    worker = Worker(Path("unused"), Path("unused"), "test")
    worker.program = MagicMock()
    worker.pg = MagicMock()
    worker.pg.program_info.return_value.getBoolean.return_value = True
    worker.methods = lambda: [{"class_name": "Store", "selector": "save:", "imp": 4096}]
    status, data = worker.execute("dispatch_candidates", {"selector": "save:"})
    assert status == "partial"
    assert data["receiver_resolved"] is False
    assert data["ambiguous"] is True
    assert data["candidates"][0]["certainty"] == "candidate"


@pytest.mark.integration
def test_real_ghidra_fixture(tmp_path):
    """Opt-in real test: AIRE_GHIDRA_TEST_BINARY must point to a native fixture."""
    import os

    path = os.environ.get("AIRE_GHIDRA_TEST_BINARY")
    if not path:
        pytest.skip("Set AIRE_GHIDRA_TEST_BINARY with Ghidra and JDK configured")
    project_dir = tmp_path / ".aire" / "project"
    with GhidraBackend(project_dir, Path(path), "real-fixture", timeout=300) as engine:
        result = engine.query("analyze", timeout=240)
        assert result.status == "ok", result.to_dict()
        assert result.data["function_count"] > 0
        functions = engine.query("functions", limit=10)
        assert functions.status in {"ok", "partial"}
        assert functions.data["functions"]
        address = functions.data["functions"][0]["address"]
        pseudocode = engine.query("decompile", address=address)
        assert pseudocode.status == "ok", pseudocode.to_dict()
        assert pseudocode.data["pseudocode"]
        cached = engine.query("analyze")
        assert cached.data["cached"] is True
    # This opens through a new temporary alias and must find the same database.
    with GhidraBackend(project_dir, Path(path), "real-fixture", timeout=300) as reopened:
        assert reopened.query("analyze").data["cached"] is True
