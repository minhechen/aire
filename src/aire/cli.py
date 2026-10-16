"""Command-line workflow for local, evidence-led investigations."""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .environment import find_swift_demangler
from .report import export_case, validate_report
from .tools import Toolbox, offline_investigate
from .workspace import Workspace

app = typer.Typer(no_args_is_help=True, invoke_without_command=True, help="Local iOS analysis tools for your agent, via MCP or CLI.",
                  pretty_exceptions_enable=False)
console = Console(markup=False)
Root = Annotated[Path, typer.Option("--workspace", "-w", envvar="AIRE_WORKSPACE",
                                   help="Local private workspace (default: .aire).")]


def _workspace(ctx: typer.Context) -> Workspace:
    return Workspace(ctx.obj["workspace"])


def _fail(exc: Exception) -> None:
    console.print(f"Error: {exc}", style="red")
    raise typer.Exit(1)


def _show_json(data) -> None:
    typer.echo(json.dumps(data, ensure_ascii=False, indent=2))


@app.callback()
def main(ctx: typer.Context, workspace: Root = Path(".aire"),
         version: Annotated[bool, typer.Option("--version", is_eager=True)] = False):
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    ctx.obj = {"workspace": workspace}


@app.command()
def doctor(json_output: Annotated[bool, typer.Option("--json")] = False):
    """Check the local toolchain. Never download or execute an app."""
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR")
    java_home = os.environ.get("JAVA_HOME")
    java = str(Path(java_home) / "bin" / "java") if java_home else shutil.which("java")
    java_info = "not installed"
    if java:
        try:
            proc = subprocess.run([java, "-version"], check=False, capture_output=True, text=True, timeout=10)
            java_info = ((proc.stderr or proc.stdout).splitlines() or ["unknown"])[0]
            java_ok = proc.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            java_ok = False
    else:
        java_ok = False
    checks = {"aire": __version__, "python": platform.python_version(),
              "python_architecture": platform.machine(), "java": java_info,
              "java_available": java_ok, "ghidra_install_dir": ghidra,
              "ghidra_available": bool(ghidra and (Path(ghidra) / "Ghidra").is_dir()),
              "pyghidra_available": importlib.util.find_spec("pyghidra") is not None,
              "swift_demangler": find_swift_demangler(),
              "lief_available": importlib.util.find_spec("lief") is not None,
              "mcp_available": importlib.util.find_spec("mcp") is not None,
              "primary_agent_mode": "external agent via MCP",
              "model_configured": bool(os.environ.get("AIRE_BASE_URL") and os.environ.get("AIRE_MODEL"))}
    checks["code_analysis_ready"] = bool(checks["java_available"] and checks["ghidra_available"] and checks["pyghidra_available"])
    checks["note"] = "MCP uses your host agent's model; aire needs no model API configuration for that workflow. model_configured applies only to optional standalone ask. Code analysis requires a compatible Ghidra toolchain; run analyze to validate it."
    if json_output:
        _show_json(checks)
    else:
        for key, value in checks.items():
            console.print(f"{key}: {value}")


@app.command()
def mcp(ctx: typer.Context,
        tool_timeout: Annotated[float, typer.Option("--tool-timeout", min=1, max=3600)] = 180):
    """Serve local analysis tools over MCP stdio; uses the host agent's model."""
    from .mcp_server import serve

    serve(ctx.obj["workspace"], tool_timeout=tool_timeout)


@app.command()
def setup(ctx: typer.Context,
          client: Annotated[str, typer.Option("--client", help="codex or claude-code")] = "codex",
          project: Annotated[Path, typer.Option("--project", help="Project directory for local configuration.")] = Path("."),
          write: Annotated[bool, typer.Option("--write", help="Apply the previewed project-local configuration and skill.")] = False):
    """Preview or write project-local MCP registration and the investigation skill."""
    from .setup import setup_project

    try:
        _show_json(setup_project(client, project, ctx.obj["workspace"], write=write))
    except (ValueError, OSError, RuntimeError) as exc:
        _fail(exc)


@app.command("import")
def import_package(ctx: typer.Context, ipa: Path,
                   json_output: Annotated[bool, typer.Option("--json")] = False):
    """Import an IPA into a local workspace without executing it."""
    store = _workspace(ctx)
    try:
        project = store.import_ipa(ipa)
        if json_output:
            _show_json(project)
        else:
            console.print(f"Imported {project['app_name']} ({project['bundle_id']})")
            console.print(f"Project: {project['id']}")
            for image in project["images"]:
                console.print(f"  {image['architecture']} {image['status']}: {image['path']}")
            for warning in project["warnings"]:
                console.print(f"Warning: {warning}", style="yellow")
    except (ValueError, OSError) as exc:
        _fail(exc)
    finally:
        store.close()


@app.command()
def projects(ctx: typer.Context):
    """List locally imported projects."""
    store = _workspace(ctx)
    try:
        table = Table("Project", "App", "Bundle", "Images")
        for project in store.projects():
            table.add_row(project["id"], project["app_name"], project["bundle_id"], str(len(project["images"])))
        console.print(table)
    finally:
        store.close()


@app.command("inspect")
def inspect_project(ctx: typer.Context, project_id: str):
    """Show the imported manifest and per-image analysis boundaries."""
    store = _workspace(ctx)
    try:
        _show_json(store.project(project_id))
    except ValueError as exc:
        _fail(exc)
    finally:
        store.close()


@app.command()
def search(ctx: typer.Context, project_id: str, query: str,
           kind: Annotated[list[str] | None, typer.Option("--kind")] = None,
           limit: Annotated[int, typer.Option(min=1, max=50)] = 20):
    """Search indexed strings, symbols, resources, and functions."""
    store = _workspace(ctx)
    try:
        _show_json(store.search(project_id, query, kind, limit))
    except ValueError as exc:
        _fail(exc)
    finally:
        store.close()


@app.command()
def analyze(ctx: typer.Context, project_id: str,
            image_id: Annotated[str | None, typer.Option("--image")] = None,
            timeout: Annotated[float, typer.Option(min=1, max=3600)] = 180):
    """Create a reusable Ghidra index for one image (main executable by default)."""
    store = _workspace(ctx)
    tools = None
    try:
        images = store.images(project_id)
        if not images:
            raise ValueError("No Mach-O images in this package")
        selected = next((i for i in images if i.id == image_id), None) if image_id else next(
            (i for i in images if i.details.get("role") in ("main", "main_executable", "app")), images[0])
        if selected is None:
            raise ValueError("Unknown image")
        case_id = store.new_case(project_id, f"Index {selected.path}")
        tools = Toolbox(store, project_id, case_id, timeout=timeout)
        console.print(f"Analyzing {selected.path}; the initial import can take several minutes.")
        result = tools.call("analyze_image", {"image_id": selected.id})
        report = {"question": f"Index {selected.path}", "status": result.status,
                  "summary": f"Ghidra indexing: {result.status}", "claims": [],
                  "limitations": [str(result.error)] if result.error else [], "messages": []}
        store.save_case(case_id, report)
        _show_json({"case_id": case_id, **result.to_dict()})
        if result.status not in ("ok", "partial"):
            raise typer.Exit(1)
    except (ValueError, OSError) as exc:
        _fail(exc)
    finally:
        if tools:
            tools.close()
        store.close()


@app.command()
def ask(ctx: typer.Context, project_id: str, question: str,
        offline: Annotated[bool, typer.Option(help="Collect literal evidence locally, without an AI explanation.")] = False,
        case_id: Annotated[str | None, typer.Option("--case", help="Continue a previous investigation.")] = None,
        max_tools: Annotated[int, typer.Option(min=1, max=200)] = 30,
        max_seconds: Annotated[float, typer.Option(min=1, max=3600)] = 180,
        max_tokens: Annotated[int, typer.Option(min=1000, max=1000000)] = 40000):
    """Investigate a feature; model endpoint must be explicitly configured."""
    store = _workspace(ctx)
    tools = None
    report = None
    current_case = case_id
    try:
        history = []
        store.project(project_id)
        if not question.strip() or len(question) > 8000:
            raise ValueError("Question must contain 1–8000 characters")
        if case_id:
            previous = store.case(case_id)
            if previous["project_id"] != project_id:
                raise ValueError("Case belongs to another project")
            history = previous["messages"]
        config = None
        if not offline:
            from .providers import ModelConfig
            config = ModelConfig.from_env()
        current_case = case_id or store.new_case(project_id, question)
        tools = Toolbox(store, project_id, current_case, timeout=min(max_seconds, 180),
                        total_seconds=max_seconds)
        if offline:
            report = offline_investigate(question, tools)
        else:
            from .agent import Investigator

            console.print("Using the configured model endpoint. Questions and selected tool results are sent; the IPA archive is not uploaded.")

            def event(*args, **kwargs):
                if args and isinstance(args[0], dict):
                    item = args[0]
                    console.print(f"  {item.get('type', 'activity')}: {item.get('name', item.get('tool', ''))}")
                elif args:
                    console.print("  " + str(args[0])[:200])

            investigator = Investigator(config, max_tool_calls=max_tools,
                                        max_seconds=max_seconds, max_tokens=max_tokens)
            report = investigator.run(question, tools, history=history, on_event=event)
        report["question"] = question
        report = validate_report(report, store.evidence_for_case(current_case))
        store.save_case(current_case, report)
        console.print(f"Case: {current_case} · {report.get('status', 'partial')}")
        console.print(report.get("summary", ""))
        for claim in report.get("claims", []):
            console.print(f"[{claim['kind']}] {claim['text']}")
        for limitation in report.get("limitations", []):
            console.print(f"Unresolved: {limitation}", style="yellow")
        console.print(f"Report: {export_case(store, current_case)}")
        if report.get("status") == "error":
            raise typer.Exit(1)
    except KeyboardInterrupt:
        if current_case and tools:
            store.save_case(current_case, {"status": "interrupted", "summary": "Interrupted; collected evidence was retained.",
                                          "question": question, "claims": [], "limitations": [], "messages": history})
            console.print(f"Interrupted. Evidence retained in {current_case}.")
        raise typer.Exit(130)
    except (ValueError, OSError, RuntimeError) as exc:
        if current_case and tools:
            store.save_case(current_case, {"status": "error", "summary": "Investigation stopped.",
                                          "question": question, "claims": [], "limitations": [str(exc)], "messages": history})
        _fail(exc)
    finally:
        if tools:
            tools.close()
        store.close()


@app.command()
def report(ctx: typer.Context, case_id: str,
           format: Annotated[str, typer.Option("--format", "-f")] = "html",
           output: Annotated[Path | None, typer.Option("--output", "-o")] = None):
    """Export a self-contained report and its evidence."""
    store = _workspace(ctx)
    try:
        console.print(str(export_case(store, case_id, format, output)))
    except (ValueError, OSError) as exc:
        _fail(exc)
    finally:
        store.close()


@app.command()
def evidence(ctx: typer.Context, evidence_id: str):
    """Inspect a recorded tool result, provenance, and output digest."""
    store = _workspace(ctx)
    try:
        _show_json(store.evidence(evidence_id))
    except ValueError as exc:
        _fail(exc)
    finally:
        store.close()


@app.command()
def replay(ctx: typer.Context, evidence_id: str):
    """Rerun one saved tool invocation and compare its canonical output hash."""
    store = _workspace(ctx)
    tools = None
    try:
        item = store.evidence(evidence_id)
        case_id = store.new_case(item["project_id"], f"Replay {evidence_id}")
        tools = Toolbox(store, item["project_id"], case_id)
        result = tools.call(item["tool"], item["params"])
        new = store.evidence(result.evidence_ids[0])
        matches = new["digest"] == item["digest"]
        store.save_case(case_id, {"status": "complete" if matches else "partial", "claims": [],
                                  "summary": f"Replay output {'matches' if matches else 'differs'}", "messages": []})
        _show_json({"matches": matches, "original": item["digest"], "replayed": new["digest"],
                    "case_id": case_id, "note": "Model wording is not replayed."})
        if not matches:
            raise typer.Exit(1)
    except (ValueError, OSError) as exc:
        _fail(exc)
    finally:
        if tools:
            tools.close()
        store.close()


@app.command()
def cases(ctx: typer.Context, project_id: str):
    """List saved investigations for a project."""
    store = _workspace(ctx)
    try:
        store.project(project_id)
        _show_json([dict(r) for r in store.db.execute(
            "SELECT id,question,status,updated_at FROM cases WHERE project_id=? ORDER BY updated_at DESC", (project_id,))])
    except ValueError as exc:
        _fail(exc)
    finally:
        store.close()


@app.command()
def delete(ctx: typer.Context, project_id: str,
           yes: Annotated[bool, typer.Option("--yes", help="Confirm deletion of local project, evidence, and reports.")] = False):
    """Delete an imported local project. The original IPA is untouched."""
    store = _workspace(ctx)
    try:
        store.project(project_id)
        if not yes:
            typer.confirm(f"Delete local project {project_id} and its evidence?", abort=True)
        store.delete_project(project_id)
        console.print(f"Deleted {project_id}.")
    except ValueError as exc:
        _fail(exc)
    finally:
        store.close()
