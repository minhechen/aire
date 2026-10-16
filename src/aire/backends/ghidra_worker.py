"""Private CPython/JVM JSONL worker. No Ghidra imports occur in aire itself."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import traceback
from importlib.metadata import version
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
METHOD_PATTERN = re.compile(r"^([+-])\[([^\]]+?)\s+([^\]]+)\]$")


def address_value(address: Any) -> int:
    return int(address.getOffset()) & ((1 << 64) - 1)


def parse_objc_name(
    name: str, namespace: str = "", known_classes: set[str] | None = None
) -> dict[str, str] | None:
    """Read names supplied by Ghidra; do not infer ObjC methods from arbitrary code."""
    match = METHOD_PATTERN.fullmatch(name)
    if match:
        return {"method_kind": match[1], "class_name": match[2], "selector": match[3]}
    # Ghidra's Objective-C analyzer also creates Class::method namespaces.
    # These are accepted only inside its explicitly named Objective-C tree.
    parts = namespace.split("::")
    if any(p.lower() in {"objc", "objective-c", "objectivec"} for p in parts) and parts[-1]:
        return {"method_kind": "unknown", "class_name": parts[-1], "selector": name}
    if known_classes and namespace in known_classes:
        return {"method_kind": "unknown", "class_name": namespace, "selector": name}
    return None


class Worker:
    def __init__(
        self, project_dir: Path, binary: Path, image_id: str, ghidra_dir: Path | None = None
    ) -> None:
        self.project_dir, self.binary, self.image_id = project_dir, binary, image_id
        self.ghidra_dir = ghidra_dir or project_dir
        self.project = self.program = self.consumer = self.decompiler = None
        self.pg = None
        self.hash = ""
        self.versions: dict[str, str] = {"name": "ghidra"}

    def initialize(self) -> None:
        if self.program is not None:
            return
        import pyghidra
        from pyghidra.launcher import HeadlessPyGhidraLauncher

        self.pg = pyghidra
        runtime_home = self.project_dir / "runtime-home"
        runtime_home.mkdir(parents=True, exist_ok=True)
        launcher = HeadlessPyGhidraLauncher(install_dir=Path(os.environ["GHIDRA_INSTALL_DIR"]))
        launcher.add_vmargs(f"-Duser.home={runtime_home}")
        # Respect an explicitly configured JDK without LaunchSupport writing to
        # the user's normal Ghidra settings directory.
        if os.environ.get("JAVA_HOME"):
            launcher.java_home = Path(os.environ["JAVA_HOME"])
        launcher.start()
        from ghidra.framework import Application
        from java.io import File

        self.versions.update(
            {"ghidra": str(Application.getApplicationVersion()), "pyghidra": version("pyghidra")}
        )

        digest = hashlib.sha256()
        with self.binary.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        self.hash = digest.hexdigest()
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self.project = pyghidra.open_project(
            str(self.ghidra_dir), "image-" + self.hash[:24], create=True
        )
        program_name = "image"
        if self.project.getProjectData().getFile("/" + program_name) is None:
            loader = pyghidra.program_loader().project(self.project).source(File(str(self.binary)))
            with loader.name(program_name).load() as loaded:
                loaded.save(pyghidra.task_monitor())
        self.program, self.consumer = pyghidra.consume_program(self.project, "/" + program_name)

    def addr(self, value: Any) -> Any:
        if value is None:
            raise ValueError("An address is required")
        integer = int(value, 0) if isinstance(value, str) else int(value)
        return self.program.getAddressFactory().getDefaultAddressSpace().getAddress(hex(integer))

    def function(self, value: Any) -> Any:
        address = self.addr(value)
        function = self.program.getFunctionManager().getFunctionAt(address)
        if function is None:
            function = self.program.getFunctionManager().getFunctionContaining(address)
        if function is None:
            raise ValueError(f"No function contains address {address}")
        return function

    def function_data(self, function: Any) -> dict[str, Any]:
        return {
            "image_id": self.image_id,
            "address": address_value(function.getEntryPoint()),
            "name": str(function.getName(True)),
            "size": int(function.getBody().getNumAddresses()),
            "metadata": {
                "external": bool(function.isExternal()),
                "thunk": bool(function.isThunk()),
                "signature": str(function.getSignature()),
            },
        }

    def analyze(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        options = self.pg.program_info(self.program)
        cached = options.getBoolean("AIRE.AnalysisComplete", False)
        log = ""
        if not cached:
            from ghidra.app.plugin.core.analysis import AutoAnalysisManager
            from jpype import JProxy

            monitor = self.pg.task_monitor(int(params.get("timeout", 100)))
            completed = {"cancelled": False}

            def analysis_ended(_manager: Any, cancelled: Any) -> None:
                completed["cancelled"] = bool(cancelled)

            listener = JProxy(
                "ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener",
                dict={"analysisEnded": analysis_ended},
            )
            manager = AutoAnalysisManager.getAnalysisManager(self.program)
            manager.addListener(listener)
            try:
                log = self.pg.analyze(self.program, monitor)
            finally:
                manager.removeListener(listener)
            # PyGhidra 3.1 deliberately cancels the monitor *after* successful
            # analysis to stop its timer. Capture Ghidra's actual end event.
            if completed["cancelled"]:
                self.program.save("aire partial analysis", self.pg.task_monitor())
                return "partial", {"analysis_complete": False, "analysis_log": str(log)[-20000:]}
            with self.pg.transaction(self.program, "aire analysis marker"):
                options.setBoolean("AIRE.AnalysisComplete", True)
            self.program.save("aire analysis", self.pg.task_monitor())
        return "ok", {
            "analysis_complete": True,
            "cached": bool(cached),
            "sha256": self.hash,
            "language": str(self.program.getLanguageID()),
            "imagebase": address_value(self.program.getImageBase()),
            "function_count": int(self.program.getFunctionManager().getFunctionCount()),
            "analysis_log": str(log)[-20000:],
        }

    def methods(self) -> list[dict[str, Any]]:
        methods = []
        classes = set()
        for symbol in self.program.getSymbolTable().getAllSymbols(True):
            namespace = str(symbol.getParentNamespace().getName(True))
            if namespace in {"objc::class_t", "objc::class_rw_t", "objc::class_ro_t"}:
                classes.add(str(symbol.getName()))
        for function in self.program.getFunctionManager().getFunctions(True):
            parsed = parse_objc_name(
                str(function.getName()), str(function.getParentNamespace().getName(True)), classes
            )
            if parsed:
                methods.append(
                    {
                        **parsed,
                        "image_id": self.image_id,
                        "imp": address_value(function.getEntryPoint()),
                        "name": str(function.getName(True)),
                        "source": "ghidra_symbol",
                        "certainty": "observed",
                    }
                )
        return methods

    def reference_data(self, reference: Any) -> dict[str, Any]:
        destination = reference.getToAddress()
        target = self.program.getFunctionManager().getFunctionAt(destination)
        source = self.program.getFunctionManager().getFunctionContaining(reference.getFromAddress())
        target_name = str(target.getName(True)) if target else ""
        kind = str(reference.getReferenceType())
        override = "OVERRIDE" in kind
        computed = bool(reference.getReferenceType().isComputed())
        dynamic = bool("objc_msgSend" in target_name or target_name.startswith("objc_stub::"))
        return {
            "image_id": self.image_id,
            "from_address": address_value(reference.getFromAddress()),
            "to_address": address_value(destination),
            "kind": kind,
            "certainty": "candidate" if override or computed else "observed",
            "from_function": address_value(source.getEntryPoint()) if source else None,
            "target_name": target_name or None,
            "metadata": {
                "dynamic_dispatch": dynamic,
                "analysis_override": override,
                "computed": computed,
                "dispatch_selector": target_name.removeprefix("objc_stub::")
                if target_name.startswith("objc_stub::")
                else None,
                "destination_space": str(destination.getAddressSpace().getName()),
            },
        }

    def execute(self, operation: str, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        supported = {
            "analyze",
            "functions",
            "xrefs",
            "calls",
            "decompile",
            "objc_methods",
            "dispatch_candidates",
        }
        if operation not in supported:
            return "unsupported", {"reason": f"Unknown operation: {operation}"}
        self.initialize()
        if operation == "analyze":
            return self.analyze(params)
        if not self.pg.program_info(self.program).getBoolean("AIRE.AnalysisComplete", False):
            status, data = self.analyze(params)
            if status != "ok":
                return status, data
        limit = min(max(int(params.get("limit", 500)), 1), 5000)
        offset = max(int(params.get("offset", 0)), 0)
        if operation == "functions":
            if params.get("address") is not None:
                return "ok", {"functions": [self.function_data(self.function(params["address"]))]}
            query = str(params.get("query", params.get("name", ""))).casefold()
            matches = []
            for function in self.program.getFunctionManager().getFunctions(True):
                if not query or query in str(function.getName(True)).casefold():
                    matches.append(self.function_data(function))
                    if len(matches) >= offset + limit + 1:
                        break
            truncated = len(matches) > offset + limit
            return ("partial" if truncated else "ok"), {
                "functions": matches[offset : offset + limit],
                "offset": offset,
                "next_offset": offset + limit if truncated else None,
            }
        if operation == "objc_methods":
            matches = self.methods()
            query = str(params.get("query", "")).casefold()
            matches = [method for method in matches if query in method["name"].casefold()]
            return ("partial" if len(matches) > offset + limit else "ok"), {
                "methods": matches[offset : offset + limit],
                "total": len(matches),
            }
        if operation == "dispatch_candidates":
            selector = str(params.get("selector", ""))
            if not selector:
                return "unsupported", {
                    "reason": "Provide a recovered selector; callsite receiver analysis is not supported in v0.1.",
                    "candidates": [],
                    "receiver_resolved": False,
                }
            matches = [method for method in self.methods() if method["selector"] == selector]
            for match in matches:
                match["certainty"] = "candidate"
            return "partial", {
                "selector": selector,
                "candidates": matches[:limit],
                "receiver_resolved": False,
                "ambiguous": True,
                "reason": "Selector match only; receiver identity and runtime dispatch are unconfirmed.",
            }
        if operation == "xrefs":
            address = self.addr(params.get("address"))
            manager = self.program.getReferenceManager()
            direction = params.get("direction", "to")
            if direction not in {"to", "from", "both"}:
                raise ValueError("direction must be to, from, or both")
            matches = []
            if direction in {"to", "both"}:
                for reference in manager.getReferencesTo(address):
                    matches.append(self.reference_data(reference))
                    if len(matches) > limit:
                        break
            if direction in {"from", "both"} and len(matches) <= limit:
                matches.extend(
                    self.reference_data(ref) for ref in manager.getReferencesFrom(address)
                )
            return ("partial" if len(matches) > limit else "ok"), {"references": matches[:limit]}
        function = self.function(params.get("address"))
        if operation == "calls":
            matches = []
            for instruction in self.program.getListing().getInstructions(function.getBody(), True):
                for reference in instruction.getReferencesFrom():
                    if reference.getReferenceType().isCall():
                        matches.append(self.reference_data(reference))
                        if len(matches) > limit:
                            break
                if len(matches) > limit:
                    break
            return ("partial" if len(matches) > limit else "ok"), {
                "address": address_value(function.getEntryPoint()),
                "references": matches[:limit],
                "scope": "Ghidra call references; unresolved indirect calls may be absent",
            }
        from ghidra.app.decompiler import DecompInterface

        if self.decompiler is None:
            self.decompiler = DecompInterface()
            if not self.decompiler.openProgram(self.program):
                raise RuntimeError("Ghidra decompiler could not open program")
        seconds = min(max(int(params.get("timeout", 30)), 1), 300)
        result = self.decompiler.decompileFunction(function, seconds, self.pg.task_monitor(seconds))
        if not result.decompileCompleted() or result.getDecompiledFunction() is None:
            return "partial", {
                "address": address_value(function.getEntryPoint()),
                "pseudocode": "",
                "reason": str(result.getErrorMessage()),
            }
        return "ok", {
            "address": address_value(function.getEntryPoint()),
            "name": str(function.getName(True)),
            "pseudocode": str(result.getDecompiledFunction().getC()),
            "representation": "decompiler_pseudocode",
            "limitations": [
                "Pseudocode may include Ghidra-inferred Objective-C call targets; runtime receiver identities are unconfirmed."
            ],
        }

    def close(self) -> None:
        if self.decompiler is not None:
            self.decompiler.dispose()
        if self.program is not None:
            self.program.release(self.consumer)
        if self.project is not None:
            self.project.close()


def main() -> None:
    # Executing this file puts backends/ on sys.path. Remove it so ghidra.py
    # cannot shadow the Java ``ghidra`` package installed by PyGhidra.
    worker_dir = Path(__file__).resolve().parent
    sys.path[:] = [entry for entry in sys.path if Path(entry).resolve() != worker_dir]
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-dir", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--ghidra-dir", type=Path)
    args = parser.parse_args()
    # Java can write directly to fd 1, bypassing contextlib.redirect_stdout.
    # Keep a duplicate exclusively for JSONL, then redirect fd 1 to the log.
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), "w", encoding="utf-8", buffering=1)
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    worker = Worker(args.project_dir, args.binary, args.image_id, args.ghidra_dir)
    try:
        for line in sys.stdin:
            request_id = None
            try:
                request = json.loads(line)
                request_id = request.get("request_id")
                if request.get("schema_version") != SCHEMA_VERSION:
                    raise ValueError("Unsupported schema_version")
                if not isinstance(request_id, str) or not isinstance(request.get("params"), dict):
                    raise TypeError("request_id and object params are required")
                status, data = worker.execute(request.get("operation", ""), request["params"])
                response = {
                    "schema_version": SCHEMA_VERSION,
                    "request_id": request_id,
                    "status": status,
                    "data": {
                        **data,
                        "image_id": args.image_id,
                        "backend": worker.versions,
                        "input_sha256": worker.hash or None,
                    },
                }
            except Exception as exc:  # noqa: BLE001 - isolate Java/JPype failures at protocol boundary
                traceback.print_exc(file=sys.stderr)
                dependency = isinstance(exc, (ImportError, ModuleNotFoundError))
                response = {
                    "schema_version": SCHEMA_VERSION,
                    "request_id": request_id,
                    "status": "unsupported" if dependency else "error",
                    "data": {"image_id": args.image_id},
                    "error": {
                        "code": "dependency_error" if dependency else "analysis_error",
                        "message": f"{type(exc).__name__}: {exc}",
                    },
                }
            protocol.write(json.dumps(response, ensure_ascii=False, allow_nan=False) + "\n")
            protocol.flush()
    finally:
        worker.close()
        protocol.close()


if __name__ == "__main__":
    main()
