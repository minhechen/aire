# aire

**Android & iOS Reverse Engineering**

Ask how an app feature works. Follow the implementation and inspect the evidence.

`aire` gives your existing Agent local reverse engineering tools through MCP. Import
an IPA, ask how a feature works, and let the Agent query resources, Mach-O images
and Ghidra for functions, references, calls and approximate pseudocode. Findings
link to saved tool results with input and output hashes.

**v0.1 is experimental and iOS-first.** Android is a future platform adapter in this
repository. Your host Agent owns the model and conversation; aire provides analysis,
evidence and reports. The MCP workflow needs no separate model API configuration.
Local CLI tools and an optional standalone `ask` command are also available.

## Install from this repository

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
aire doctor
```

The project is named `aire`. Install from this checkout; the unrelated public PyPI
package named `aire` is not this project.

For code analysis, install Ghidra and its matching JDK, then:

```bash
python -m pip install -e '.[ghidra]'
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
export JAVA_HOME=/absolute/path/to/jdk
aire doctor
```

See [Ghidra setup](docs/ghidra.md) for the tested versions, macOS native components,
architecture requirements, and failure diagnostics. Python 3.11+ is supported. Import
uses a bounded, standard-library Mach-O reader; it does not require LIEF Extended.

## Connect your Agent

For project-local Codex setup, preview first, then apply:

```bash
aire setup --client codex --project .
aire setup --client codex --project . --write
```

This writes project-local MCP configuration and copies the packaged
`aire-investigate` skill; it does not install global settings. Open this trusted
project in your host, reload/restart the MCP connection as needed, and verify that
the aire tools are connected. Setup does not inject tools into an already-running
conversation.

Then ask your Agent:

> Use $aire-investigate to import /absolute/path/to/App.ipa and explain how its
> favorites feature works. Cite the evidence and export an HTML report.

The Agent selects or imports a project, starts an investigation case, follows
relevant code, saves findings with evidence IDs, and exports the requested report.
You can continue with follow-up questions in the same case.

The server entry point is `aire mcp` (stdio). For another MCP host, or manual
absolute-path configuration, see [MCP setup and tool lifecycle](docs/mcp.md).
`aire doctor` reporting `model_configured: False` does **not** block this workflow;
that field only applies to standalone `aire ask`.

## Use the local CLI

Import and inspect an existing package without any model configuration:

```bash
aire import /absolute/path/to/App.ipa
aire projects
aire inspect <project-id>
aire search <project-id> FavoriteStore
aire analyze <project-id>
```

The initial Ghidra analysis can take minutes; later queries reuse the saved project.
To try a genuine iOS sample on macOS with Xcode and the iOS SDK:

```bash
python examples/build_ios_demo.py
aire import .aire/demo/AireDemo.ipa
aire projects
```

Copy the project ID printed by `import`:

```bash
aire search <project-id> FavoriteStore
aire analyze <project-id>
```

Ask the connected Agent to investigate that project ID, or collect literal
observations locally:

```bash
aire ask <project-id> FavoriteStore --offline
aire report <case-id> --format html
aire report <case-id> --format json --output investigation.json
```

The sample contains real Objective-C/UIKit code for NSUserDefaults storage, a network
request with a completion block, and two unrelated methods sharing a selector. The
builder compiles but never signs, installs, or executes it. A stripped variant and
source-grounded questions are documented in [the demo](examples/ios-demo/README.md).

Offline mode is explicitly partial: it returns literal matches, not an AI explanation.
It cannot translate a feature question into code keywords or prove feature behavior.

## Optional: standalone `ask`

Use this only if you want aire itself to run the investigation loop without an
external Agent. This mode requires an explicitly configured model endpoint. MCP
users can skip this section.

The transport implements the Chat Completions tool-call protocol. There is no default
model endpoint and no automatic discovery of cloud credentials.

For a local server implementing that protocol:

```bash
export AIRE_BASE_URL=http://127.0.0.1:1234/v1
export AIRE_MODEL=your-tool-capable-model
```

For a remote provider, set an HTTPS base URL, a supported model ID, and `AIRE_API_KEY`.
Do not put keys in source files or reports. Not every provider/model supports tools or
the `max_completion_tokens` field; compatibility must be checked with your server.

`ask` sends the question, tool schemas, and selected tool results to that endpoint.
It does not upload the IPA archive. Tool results can include proprietary code and strings.
Local endpoints work without a key; remote endpoints require one. Redirects are refused.

```bash
aire ask <project-id> 'How is the verification request constructed?' \
  --max-tools 30 --max-seconds 180 --max-tokens 40000
aire ask <project-id> 'What happens if the request fails?' --case <case-id>
```

Input token use is estimated before requests and reconciled with provider usage when
available. These are operational bounds, not a billing guarantee. Collected evidence
remains available when a budget or a tool fails.

## What v0.1 supports

| Area | Behavior |
| --- | --- |
| IPA import | Bounded extraction; main app, frameworks, extensions; original archive preserved |
| Inventory | Thin/fat Mach-O, per-slice encryption, load commands, imports/symbols, readable strings/resources |
| Code investigation | Unencrypted arm64 images via Ghidra; on-demand pseudocode, references and callsites |
| ObjC | Declared methods and selector candidates; no claim of complete receiver/dispatch resolution |
| Swift | Surviving symbols and Ghidra capabilities; optimized/stripped/SwiftUI recovery is limited |
| Findings | Observation / inference / unknown; invalid references demoted; structural checks are not semantic verification |
| Agent integration | Local stdio MCP tools and a packaged investigation skill; host supplies the model |
| Persistence | Reusable analysis projects, cases and evidence; standalone `ask` also saves its conversation |
| Export | Self-contained HTML, escaped Markdown, JSON investigation packet |

Encrypted images are excluded from code analysis. Readable resources and other images
remain searchable. A clear encryption flag does not prove a binary is unobfuscated.
Flutter, Unity and React Native receive runtime hints rather than dedicated deep analysis.
System framework implementation is outside the initial investigation scope.

String matches, imported SDKs, and same-selector methods are leads. Static analysis does
not prove a runtime path or server behavior. Pseudocode is never presented as original source.

## Evidence and local data

```bash
aire evidence <evidence-id>
aire replay <evidence-id>
aire cases <project-id>
aire --workspace /path/to/workspace projects
aire delete <project-id> --yes
```

Data defaults to `.aire/` in the current directory; `AIRE_WORKSPACE` or `--workspace`
changes it. The workspace holds extracted files, indexes, analysis projects, evidence,
conversations, and generated reports. `delete` removes local project records and default
reports; copies exported elsewhere remain yours to manage. The source IPA is untouched.

Replay reruns a saved tool invocation and compares canonical output hashes. An index or
tool-version change may produce a different output; model wording is not replayed.
Reports contain the saved parameters, results, output digests, and provenance.

## Development and validation

```bash
python -m pytest -q
ruff check src tests examples
```

External-tool integration tests are opt-in:

```bash
AIRE_TEST_XCODE=1 python -m pytest tests/test_demo.py -q
AIRE_GHIDRA_TEST_BINARY=/absolute/path/to/arm64-binary \
  python -m pytest tests/test_ghidra.py -q
```

Provider tests use a local HTTP test server. They make no paid API calls. Synthetic
fixtures test archive and binary-format edge cases; Xcode/Ghidra tests use actual
compiled binaries. [Benchmark questions](examples/benchmark.json) contain expected
source-grounded answers, with agent results explicitly unevaluated until measured.
No general feature-investigation success rate is claimed for v0.1.

See [architecture](docs/architecture.md) and [validation](docs/validation.md).

## License

MIT. Ghidra is a separate dependency under its own license; it is not bundled in the
Python distribution.
