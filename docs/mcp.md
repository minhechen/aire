# Use aire from an existing Agent

aire's primary workflow is a local stdio MCP server plus the `aire-investigate`
skill. Your host Agent handles the model, tool selection and conversation. aire
imports the IPA, runs analysis tools, saves evidence and exports reports. It makes
no model requests in this mode and needs no `AIRE_BASE_URL`, `AIRE_MODEL` or
`AIRE_API_KEY`. `doctor` reporting `model_configured: False` only concerns the
optional standalone `ask` command.

## Project-local Codex setup

Install aire in a virtual environment and configure Ghidra/JDK first; see
[the README](../README.md) and [Ghidra setup](ghidra.md). From the project directory:

```bash
aire setup --client codex --project .
aire setup --client codex --project . --write
```

The first command previews the setup. `--write` applies the project-local MCP
configuration and copies the packaged investigation skill. It does not install
global configuration or create a second model configuration. Inspect the preview
for exact paths and launch arguments before applying it.

Open the same trusted project in your host. Reload/restart its MCP connection as
needed, and verify that the aire tools and `aire-investigate` skill are available
in the session before asking it to investigate. Writing config does not make new
tools available in an already-running conversation automatically. Host permission
settings still apply to local tool access.

Example request after connection:

> Use $aire-investigate to import /absolute/path/to/App.ipa and explain how the
> favorites feature stores and restores data. Cite the evidence and export an
> HTML report.

Codex supports project `.codex/config.toml` for trusted projects and repository
skills under `.agents/skills`. See the official [MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
and [skill discovery](https://learn.chatgpt.com/docs/build-skills) documentation for
the host's configuration and loading behavior.

For Claude Code, the equivalent project-local setup is:

```bash
aire setup --client claude-code --project .
aire setup --client claude-code --project . --write
```

It uses `.mcp.json` and `.claude/skills/aire-investigate`. Claude Code requires its
own project MCP approval; follow the host's prompt, then invoke `/aire-investigate`
with your feature question. See the official [MCP](https://code.claude.com/docs/en/mcp)
and [skills](https://code.claude.com/docs/en/skills) documentation.

## Manual stdio connection

Any local MCP-capable host can launch the server. Use an absolute Python path
inside the environment where aire and its dependencies are installed, and an
absolute workspace path so the connection is independent of the host's directory:

```text
command: /absolute/path/to/aire/.venv/bin/python
args: ["-m", "aire", "--workspace", "/absolute/path/to/private/.aire", "mcp"]
```

The equivalent command to try directly is:

```bash
/absolute/path/to/aire/.venv/bin/python -m aire \
  --workspace /absolute/path/to/private/.aire mcp
```

The server waits for MCP input on stdin. Standard output is reserved for protocol
messages; diagnostics go to stderr. It does not open a network listener.

A Codex TOML example, using the host's `env_vars` allowlist for toolchain values:

```toml
[mcp_servers.aire]
command = "/absolute/path/to/aire/.venv/bin/python"
args = ["-m", "aire", "--workspace", "/absolute/path/to/private/.aire", "mcp"]
env_vars = ["GHIDRA_INSTALL_DIR", "JAVA_HOME", "GHIDRA_SWIFT_DEMANGLER", "DEVELOPER_DIR"]
startup_timeout_sec = 30
tool_timeout_sec = 240
```

The host process must have those environment variables to forward them. A GUI
launched independently of your shell may not inherit your shell configuration;
set required toolchain paths in the host's MCP environment configuration if needed.
Only toolchain settings are needed; do not add model credentials to this entry.
For another host, translate command, args and environment into its documented
configuration format. Copy the packaged `aire-investigate` skill into that host's
supported skill location when desired; the MCP tools remain usable without it.

## Investigation lifecycle

Tool names may have a host-specific prefix; their server names are:

| Task | Tools |
| --- | --- |
| Select input | `list_projects`, `import_ipa(ipa_path)`, `inspect_project(project_id)` |
| Create or resume a case | `start_investigation(project_id, question)`, `get_investigation(case_id)` |
| Search and inspect images | `list_images`, `search_entities`, `analyze_image` |
| Read implementation evidence | `read_resource`, `get_function`, `get_xrefs`, `get_calls`, `decompile`, `get_dispatch_candidates` |
| Read a saved tool result | `get_evidence(case_id, evidence_id)` |
| Persist the answer | `save_findings(case_id, summary, claims, limitations)` |
| Export a requested artifact | `export_report(case_id, format)` |

All analysis tools require the active `case_id` plus their normal operation
arguments. The server resolves the project from the case and records tool evidence
in that case. Keep IDs from results instead of constructing them from display names.

The Agent can search import-time strings/resources first or analyze a relevant
image when code is needed. `analyze_image` builds a reusable index; the first run
can take minutes. An image's code-analysis restrictions do not hide readable
resources in other parts of the package. Empty searches cover the current index
only, not every possible implementation.

`save_findings` takes claims with `text`, `kind` (`observation`, `inference` or
`unknown`) and `evidence_ids`. Evidence references are checked against the case;
unsupported claims may be demoted. These are structural checks, not proof that the
Agent's interpretation is correct. Inspect the returned saved findings after writing.
The saved summary is rebuilt from the first three claims that pass citation checks;
place the implementation overview first. The submitted free-form summary is not
retained, so it cannot bypass the claim citation checks.
`export_report` writes HTML, Markdown (`md`) or JSON under the workspace's reports
directory and returns its path. Save updated findings before exporting a report.

Use `get_investigation` to resume a case, then `get_evidence` for specific results
when the host no longer has them in context. Saved findings and tool evidence
survive host conversation resets; the host's private model context is not persisted
by the MCP server.

## Boundaries and troubleshooting

- **No tools visible:** check the host's loaded MCP configuration, trusted-project
  status, executable path and connection logs. Restart/reload the connection rather
  than assuming a newly written config has activated in the current chat.
- **Ghidra unavailable:** run `aire doctor` in the configured Python environment and
  verify the MCP child receives `GHIDRA_INSTALL_DIR` and `JAVA_HOME`. Import, search
  and existing evidence inspection do not require Ghidra.
- **Timeout or partial analysis:** retain the saved result and state what remains
  unexamined. Reuse the persistent project where possible and adjust the host tool
  timeout if it is shorter than the intended analysis request.
- **No readable implementation:** encrypted images, unsupported architectures,
  optimized Swift or unresolved dynamic calls can prevent a complete explanation.
  A selector candidate, SDK import or string hit does not prove a runtime path.
- **Data handling:** aire keeps IPA extraction, indexes and reports local. Tool
  results can contain proprietary strings and pseudocode; your host controls which
  results reach its model and that model's data policy. The original IPA archive
  is not sent to a model by aire.

The MCP server has no arbitrary shell, source mutation or runtime app-execution
tool. Importing, indexing, saving findings and exporting reports do write into its
local workspace. Imported application content is untrusted analysis data.
