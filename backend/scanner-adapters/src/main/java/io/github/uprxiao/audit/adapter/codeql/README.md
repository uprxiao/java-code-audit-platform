# CodeQL Deep adapter

V1 pins CodeQL CLI `2.26.2`, `codeql/java-queries@1.11.7`, and the
`java-security-and-quality.qls` suite. The CLI and packs are local user installations governed by
the GitHub CodeQL Terms; they are never bundled in the repository or release medium.

## Integration entry point

Construct the adapter with platform-controlled absolute paths:

```java
var adapter = new CodeqlAdapter(querySuite, mavenExecutable, javaHome);
var result = new CodeqlWorkflow(executionBackend)
        .execute(adapter, scanContext, toolContext, cancellationToken);
var normalized = adapter.normalize(scanContext, result.artifacts());
```

`CodeqlWorkflow` is intentionally the execution entry point instead of the one-process
`ScannerAdapter.prepare` method. It runs two shell-free `ExecutionSpec` values in order:

1. `codeql database create --language=java --build-mode=none ...`
2. `codeql database analyze --format=sarifv2.1.0 ...`

Buildless Java extraction can invoke the server-installed `mvn` to infer the dependency graph, so
the adapter places only the validated Maven directory, JDK 17, CodeQL directory, and system binary
directories on its isolated `PATH`. It never accepts a user build-command string. Deep inherits the
separate Standard Maven build stage for build-health coverage. Generated sources and highly custom
build-time classpaths remain a documented buildless-analysis boundary.

The database is retained on create, analysis, or SARIF validation failure for task-local diagnosis.
After successful SARIF validation it is recursively deleted from the exact
`{engineOutput}/database` path. The only scanner artifact returned to reporting is
`raw/codeql/report.sarif`; phase stdout/stderr remain task logs.

## Parser guarantees

- only SARIF 2.1.0 with a non-empty `runs` array and per-run results array is accepted;
- all source locations must resolve to existing files under the staged project root;
- `codeFlows/threadFlows/locations` are preserved as real nodes;
- a flow with fewer than two nodes or any invalid node is omitted and produces a partial warning;
- missing flows never produce invented Source, Propagation, or Sink nodes;
- valid ordered flow endpoints map to Source/Sink and interior nodes map to Propagation, unless
  SARIF supplies explicit source/sink kinds;
- raw rule IDs, CWE tags, query metadata, original severity, stable fingerprint inputs, and raw
  result references are retained in Finding evidence;
- raw hit count is the number of SARIF result entries, even when a malformed item cannot normalize.

The Golden contract covers clean, findings, partial, malformed, and failed-execution states. The
opt-in real smoke fixture is an Apache-2.0 Java 17 Maven project and must produce a command-injection
path with both a real Source and Sink.
