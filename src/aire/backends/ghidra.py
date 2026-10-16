"""Isolated, persistent PyGhidra adapter.

The JVM only runs in the child process. stdout in that process is reserved for
the versioned JSONL protocol; Ghidra diagnostics go to a bounded-on-read log.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any, Self

from aire.environment import ghidra_environment
from aire.models import SCHEMA_VERSION, ToolResult

OPERATIONS = frozenset(
    {"analyze", "functions", "xrefs", "calls", "decompile", "objc_methods", "dispatch_candidates"}
)
STATUSES = frozenset({"ok", "partial", "unsupported", "error", "timeout"})


class GhidraBackend:
    """Query a single binary in a reusable Ghidra project.

    A timeout terminates the worker, which also stops JVM/decompiler work. The
    next query starts a new worker and reopens the saved project. Calls on one
    backend are serialized; separate images use separate workers/projects.
    """

    def __init__(
        self, project_dir: Path, binary_path: Path, image_id: str, timeout: float = 120
    ) -> None:
        self.project_dir = Path(project_dir).resolve()
        self.binary_path = Path(binary_path).resolve()
        self.image_id = image_id
        self.timeout = timeout
        self._process: subprocess.Popen[str] | None = None
        self._responses: queue.Queue[str | None] = queue.Queue()
        self._lock = threading.Lock()
        self._log: Any = None
        self._alias: tempfile.TemporaryDirectory[str] | None = None

    def _failure(self, status: str, code: str, message: str) -> ToolResult:
        return ToolResult(
            status=status,
            data={"image_id": self.image_id},
            error={"code": code, "message": message},
        )

    def _check_environment(self) -> ToolResult | None:
        if not self.binary_path.is_file():
            return self._failure("error", "binary_missing", "Binary file does not exist.")
        install = os.environ.get("GHIDRA_INSTALL_DIR")
        if not install or not (Path(install) / "Ghidra" / "application.properties").is_file():
            return self._failure(
                "unsupported",
                "ghidra_missing",
                "Set GHIDRA_INSTALL_DIR to an installed Ghidra 12.x directory.",
            )
        if importlib.util.find_spec("pyghidra") is None:
            return self._failure(
                "unsupported",
                "pyghidra_missing",
                "Install the optional dependency: pip install '.[ghidra]'.",
            )
        if sys.platform == "darwin":
            arch = "arm_64" if platform.machine() == "arm64" else "x86_64"
            module = Path(install) / "Ghidra" / "Features" / "Decompiler"
            candidates = [
                module / variant / "os" / f"mac_{arch}" / "decompile" for variant in ("build", "")
            ]
            if not any(path.is_file() and os.access(path, os.X_OK) for path in candidates):
                return self._failure(
                    "unsupported",
                    "ghidra_natives_missing",
                    "Build Ghidra's macOS native components using support/gradle/gradlew buildNatives; see docs/ghidra.md.",
                )
        java_home = os.environ.get("JAVA_HOME")
        if java_home:
            if not (Path(java_home) / "bin" / "java").is_file():
                return self._failure(
                    "unsupported", "java_missing", "JAVA_HOME does not contain bin/java."
                )
        else:
            java = shutil.which("java")
            try:
                usable = (
                    java
                    and subprocess.run(
                        [java, "-version"], capture_output=True, timeout=5, check=False
                    ).returncode
                    == 0
                )
            except (OSError, subprocess.TimeoutExpired):
                usable = False
            if not usable:
                return self._failure(
                    "unsupported", "java_missing", "Configure a JDK 25 with JAVA_HOME."
                )
        return None

    def _start(self) -> None:
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self._log = (self.project_dir / "worker.log").open("a", encoding="utf-8")
        worker = Path(__file__).with_name("ghidra_worker.py")
        self._responses = queue.Queue()
        ghidra_dir = self.project_dir
        if any(part.startswith(".") for part in self.project_dir.parts):
            # Ghidra 12.1's ProjectLocator rejects hidden path components.
            # The alias changes only the path presented to Java; data remains
            # in the requested persistent analysis directory.
            self._alias = tempfile.TemporaryDirectory(prefix="aire-ghidra-")
            ghidra_dir = Path(self._alias.name) / "project"
            ghidra_dir.symlink_to(self.project_dir, target_is_directory=True)
        self._process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                str(worker),
                "--project-dir",
                str(self.project_dir),
                "--binary",
                str(self.binary_path),
                "--image-id",
                self.image_id,
                "--ghidra-dir",
                str(ghidra_dir),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._log,
            text=True,
            encoding="utf-8",
            bufsize=1,
            start_new_session=os.name == "posix",
            env=ghidra_environment(),
        )
        output, responses = self._process.stdout, self._responses

        def read() -> None:
            try:
                assert output is not None
                for line in output:
                    responses.put(line)
            finally:
                responses.put(None)

        threading.Thread(target=read, name="aire-ghidra-jsonl", daemon=True).start()

    def query(self, operation: str, **params: Any) -> ToolResult:
        if operation not in OPERATIONS:
            return self._failure(
                "unsupported", "operation_unsupported", f"Unknown operation: {operation}"
            )
        with self._lock:
            unavailable = self._check_environment()
            if unavailable:
                return unavailable
            request_id = uuid.uuid4().hex
            request = {
                "schema_version": SCHEMA_VERSION,
                "request_id": request_id,
                "operation": operation,
                "params": params,
            }
            try:
                # Validate before starting a JVM or attempting to write a partial request.
                encoded = json.dumps(request, allow_nan=False)
                if self._process is None or self._process.poll() is not None:
                    self._stop()
                    self._start()
                assert self._process is not None and self._process.stdin is not None
                self._process.stdin.write(encoded + "\n")
                self._process.stdin.flush()
                line = self._responses.get(timeout=self.timeout)
                if line is None:
                    self._stop()
                    return self._failure(
                        "error", "worker_exited", "Ghidra worker exited; inspect worker.log."
                    )
                response = json.loads(line)
                if (
                    not isinstance(response, dict)
                    or response.get("schema_version") != SCHEMA_VERSION
                    or response.get("request_id") != request_id
                    or response.get("status") not in STATUSES
                    or not isinstance(response.get("data"), dict)
                    or response["data"].get("image_id") != self.image_id
                ):
                    raise ValueError("Invalid or mismatched Ghidra protocol response")
                return ToolResult(
                    status=response["status"], data=response["data"], error=response.get("error")
                )
            except queue.Empty:
                self._stop()
                return self._failure(
                    "timeout", "worker_timeout", f"Ghidra exceeded {self.timeout:g} seconds."
                )
            except (OSError, ValueError, TypeError) as exc:
                self._stop()
                return self._failure("error", "worker_protocol_error", str(exc))

    def _stop(self) -> None:
        if self._process is not None:
            if self._process.poll() is None:
                with suppress(ProcessLookupError):
                    if os.name == "posix":
                        os.killpg(self._process.pid, signal.SIGTERM)
                    else:
                        self._process.terminate()
                try:
                    self._process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    with suppress(ProcessLookupError):
                        if os.name == "posix":
                            os.killpg(self._process.pid, signal.SIGKILL)
                        else:
                            self._process.kill()
                    self._process.wait(timeout=3)
            for stream in (self._process.stdin, self._process.stdout):
                if stream is not None:
                    with suppress(OSError):
                        stream.close()
            self._process = None
        if self._log is not None:
            self._log.close()
            self._log = None
        if self._alias is not None:
            self._alias.cleanup()
            self._alias = None

    def close(self) -> None:
        with self._lock:
            # EOF lets the worker save and release the project before shutdown.
            if self._process is not None and self._process.stdin is not None:
                try:
                    self._process.stdin.close()
                    self._process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            self._stop()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
