# aire architecture

aire separates package facts, analysis output, and model interpretation. Platform
adapters produce portable entities. The primary entry point is a local stdio MCP
server: the host Agent supplies the model and calls a bounded investigation toolbox.
The toolbox reads the imported app and writes analysis/evidence into the workspace.

```text
Host Agent + aire-investigate skill
   └─ MCP (stdio) → Workspace / SQLite
       ├─ iOS importer → package files, Mach-O inventory, resource entities
       ├─ Toolbox → isolated Ghidra worker → saved analysis projects
       └─ Evidence ledger → HTML / Markdown / JSON

CLI → same workspace and analysis tools
   └─ optional Investigator → explicitly configured model endpoint
```

## Import and indexing

The importer validates every ZIP entry before extraction, rejects traversal, symlinks,
special files and case collisions, and limits extracted sizes and counts. It never
executes the application. The package SHA-256 scopes a project; image and entity IDs
are namespaced by that project to prevent shared framework collisions.

The lightweight reader inventories headers, sections, symbols, dependencies, encryption
ranges and readable data. Its direct ObjC metadata parsing is conservative and cannot
resolve every chained-fixup pointer. Ghidra supplies the primary analyzed method index.
Unsupported runtime/architecture information remains visible in the manifest.

SQLite stores projects, entities, cases and evidence. FTS5 combines symbol tokenization
with bounded substring lookup for partial names and short Chinese text. Query terms
are ORed for recall. Matches do not imply semantic relevance or feature implementation.

## Native analysis

Each image gets a persistent Ghidra project. Fat slices are extracted into analysis
inputs, leaving imported originals unchanged. A separate worker owns its JVM and
communicates through schema-versioned JSONL. Requests carry IDs and typed operations;
responses distinguish ok, partial, unsupported, error and timeout.

Analysis discovers functions and references once. Pseudocode is generated on demand.
The toolbox paginates function indexing and states truncation. A single investigation
deadline applies across worker requests; timeout terminates the worker process group.
Reopening a saved project reuses completed analysis.

Observed call instructions are separate from ObjC selector candidates. Selector lookup
returns a candidate set and `receiver_resolved=false`; the model must not turn that set
into a confirmed runtime edge. Blocks, reflection, swizzling and protocol dispatch may
leave unresolved boundaries.

## Agent and model boundary

The MCP server makes no model API requests and does not need provider credentials.
It exposes import/project inspection, case lifecycle, analysis, findings persistence
and report export. Analysis calls are scoped by case ID and preserve their evidence
links. The host owns planning, conversation and the data policy for tool results
sent to its model. The packaged `aire-investigate` skill supplies iOS investigation
and evidence-interpretation guidance without owning the host's model configuration.

The optional standalone `ask` provider is an explicit Chat Completions adapter with bounded requests, retries,
response bodies and deadlines. It refuses redirects and does not log provider response
bodies on errors. Keys are never part of persisted configuration.

Package text and tool output are untrusted data. aire exposes no shell, arbitrary
filesystem mutation, URL-fetching or arbitrary-code tool. Its structured findings
must cite saved evidence belonging to the case. Identifiers are checked; this does
not establish that a model interpreted the cited evidence correctly. Independent
host capabilities are outside aire's tool boundary.

## Evidence and reports

Evidence records include project identity, tool name, arguments, status, raw structured
result, output SHA-256 and tool provenance. Native results retain image/address context;
imported entities distinguish file evidence offsets from implementation addresses.

Reports distinguish observations, inferences and unknowns. Missing or unsuccessful
references demote claims; summaries are rebuilt when demotion changes support. HTML
escapes all untrusted content and uses a restrictive CSP without external resources.
Markdown prose is escaped; raw evidence is enclosed in safely sized fences.

## Platform boundary

`platforms/ios` owns IPA/Mach-O handling. `backends/ghidra` owns native analysis.
`models`, `workspace`, `tools`, `mcp_server`, `agent`, and `report` form the common core. An Android
adapter can add APK/DEX entities and a Java-aware backend without forcing Java method
locations into native-address-only identifiers.
