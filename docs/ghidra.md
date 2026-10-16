# Ghidra backend

aire imports and searches IPA resources without Ghidra. Function discovery,
cross references, call references and pseudocode require the optional backend.
The backend runs a real Ghidra JVM in a separate CPython process. Missing tools
produce `unsupported` results; aire does not substitute generated pseudocode.

## Install

The initial integration targets **Ghidra 12.1.4, PyGhidra 3.1.0 and JDK 25**.
Use the official binary release archive, not the GitHub source archive:

- [Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases)
- [PyGhidra API and installation](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Features/PyGhidra/src/main/py/README.md)
- [Amazon Corretto 25](https://docs.aws.amazon.com/corretto/latest/corretto-25-ug/downloads-list.html)

Install tools wherever you prefer, including the ignored `.tools/` directory.
No administrator access or global install is required.

```sh
python -m pip install -e '.[ghidra]'
export GHIDRA_INSTALL_DIR="/absolute/path/to/ghidra_12.1.4_PUBLIC"
export JAVA_HOME="/absolute/path/to/jdk/Contents/Home"
aire doctor
```

**Python and the JDK must have matching CPU architectures.** On Apple Silicon,
an Intel Homebrew Python running through Rosetta requires an x86_64 JDK. Check
the interpreter actually used by aire:

```sh
python -c 'import platform; print(platform.machine())'
"$JAVA_HOME/bin/java" -version
```

Ghidra native support binaries must also be executable on the host. The official
12.1.4 archive requires building the macOS decompiler and demangler from its
bundled sources. With Xcode command line tools installed, follow the bundled
`GettingStarted.md` instructions:

```sh
cd "$GHIDRA_INSTALL_DIR/support/gradle"
./gradlew --no-daemon buildNatives
```

The wrapper downloads Gradle on its first run. To select Intel binaries when
using an x86_64 Python/JDK on Apple Silicon, use
`:Decompiler:buildNatives_mac_x86_64 :DemanglerGnu:buildNatives_mac_x86_64` as the
tasks. aire does not execute code from an IPA.

aire discovers Swift's demangler in `PATH` or through the active Xcode toolchain
with `xcrun --find swift-demangle`. The discovered absolute path is passed to the
worker as `GHIDRA_SWIFT_DEMANGLER`; your shell environment is unchanged. An explicit
`GHIDRA_SWIFT_DEMANGLER` override takes precedence. Ghidra also has a `/usr/bin/swift`
fallback, so a missing standalone tool does not by itself establish Swift analysis
is unavailable. Swift metadata and optimized code still have the documented limits.

## Storage and protocol

Each image uses a project named with its SHA-256. Ghidra database files, local JVM
settings and `worker.log` stay in that image's analysis directory. Completed
analysis is saved in the program's `AIRE.AnalysisComplete` property and reopened
on later queries. A changed input SHA-256 creates another project. Do not open
the same Ghidra project concurrently in multiple aire processes or the GUI.
Ghidra 12.1 rejects hidden components in a project location. For `.aire` and
similar paths, the worker opens the persistent directory through an owned
temporary symlink. The parent removes that alias after stopping the worker;
the database stays in the configured workspace.

The internal JSONL request contains `schema_version`, `request_id`, `operation`
and `params`; the response echoes the first two and supplies `status`, `data`
and an optional structured `error`. Every data payload includes `image_id`.
Ghidra stdout/stderr are redirected to the log before the JVM starts so native
diagnostic messages cannot be confused with responses. On macOS, a request
timeout terminates the worker's process group, including native decompiler work.

Operations:

| Operation | Main parameters | Results |
| --- | --- | --- |
| `analyze` | `timeout` (analysis monitor, seconds) | Language, image base, function count, cache status |
| `functions` | `query`, `address`, `offset`, `limit` | Actual Ghidra functions and signatures |
| `xrefs` | `address`, `direction` (`to`, `from`, `both`), `limit` | Ghidra reference records |
| `calls` | `address`, `limit` | Call references inside a function |
| `decompile` | `address`, `timeout` | Decompiled C-like pseudocode |
| `objc_methods` | `query`, `offset`, `limit` | Methods identified by Ghidra ObjC symbol annotations |
| `dispatch_candidates` | `selector`, `limit` | Ambiguous, selector-only method candidates |

All addresses are integers in the image's virtual address space, not file
offsets. `functions(address=...)` also accepts an address inside a function.
Output lists are bounded; truncated results have `partial` status. These statuses
describe tool completion, not the confidence of the app's implementation model.

## Objective-C boundaries

`objc_methods` reads Ghidra's method names/namespaces. It is not a separate
Objective-C runtime parser. Coverage therefore depends on Ghidra's import and
analysis of the image. A call reference to `objc_msgSend` establishes a call to
the dispatcher. It does **not** establish the final receiving class or method.

The first version accepts a recovered selector for `dispatch_candidates` and
returns matching methods with `certainty=candidate`, `receiver_resolved=false`
and `ambiguous=true`, even when only one matching method is present in the image.
That method may not be the runtime target. Without a selector it returns
`unsupported`; it never chooses a method by name and labels it an observed edge.
Calls made through unresolved pointers can be absent from Ghidra's call-reference
list. Ghidra's computed and `CALL_OVERRIDE` references are exported as
`certainty=candidate`. A direct call to `objc_stub::selector` is an observed call
to a dispatcher stub, with the selector recorded separately; it does not prove
a final method target. Pseudocode may contain Ghidra's inferred dispatch
annotations and is a reverse-engineered representation, not recovered source.

## Test real analysis

Transport tests use clearly labeled protocol stubs. The integration test is
opt-in and requires a native binary fixture:

```sh
export AIRE_GHIDRA_TEST_BINARY="/absolute/path/to/unsigned-fixture"
python -m pytest tests/test_ghidra.py -m integration -v
```

The test imports and analyzes the actual file under a hidden `.aire` parent,
discovers functions, decompiles a function and reopens the saved database in a
new worker to verify the persisted analysis marker. Use the fixture builder
documented in the repository for an unsigned arm64 iOS example.
