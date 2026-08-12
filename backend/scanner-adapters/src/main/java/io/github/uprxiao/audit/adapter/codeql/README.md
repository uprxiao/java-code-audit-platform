# CodeQL Deep adapter

V1 pins CodeQL CLI `2.26.2`, `codeql/java-queries@1.11.7`, and the
`java-security-and-quality.qls` suite. The CLI and packs are local user installations governed by
the GitHub CodeQL Terms; they are never bundled in the repository or release medium.

## Integration entry point

Construct the adapter with platform-controlled absolute paths:

```java
var adapter = new CodeqlAdapter(
        querySuite, mavenExecutable, javaHome, serverMavenRepository, serverMavenSettings);
var result = new CodeqlWorkflow(executionBackend)
        .execute(adapter, scanContext, toolContext, cancellationToken);
var normalized = adapter.normalize(scanContext, result.artifacts());
```

`CodeqlWorkflow` is intentionally the execution entry point instead of the one-process
`ScannerAdapter.prepare` method. It runs four shell-free `ExecutionSpec` values in order:

1. `codeql database init --language=java --build-mode=manual ...`
2. `codeql database trace-command ... -- <fixed server Maven argv>`
3. `codeql database finalize ...`
4. `codeql database analyze --format=sarifv2.1.0 ...`

The trace phase passes a fixed argument vector directly to CodeQL: the server Maven executable,
server local repository/settings, validated profiles/properties, and fixed `clean package` goals.
There is no shell or user build-command string. Deep waits for every Standard engine before tracing,
and atomically holds both the Maven and CodeQL concurrency permits, so generated source and the real
project classpath are extracted without racing the inherited scanners.

The database is retained on create, analysis, or SARIF validation failure for task-local diagnosis.
After successful SARIF validation it is recursively deleted from the exact
task-local `codeql-db/database` path. The only scanner artifact returned to reporting is
`raw/codeql/report.sarif`; phase stdout/stderr remain task logs.

## Parser guarantees

- only SARIF 2.1.0 with a non-empty `runs` array and per-run results array is accepted;
- all source locations must resolve to existing files under the staged project root;
- `codeFlows/threadFlows/locations` are preserved as real nodes;
- a flow with fewer than two nodes or any invalid node is omitted and produces a partial warning;
- missing flows never produce invented Source, Propagation, or Sink nodes;
- only explicit SARIF/CodeQL source and sink roles are used; unlabelled nodes remain Propagation;
- raw rule IDs, CWE tags, query metadata, original severity, stable fingerprint inputs, and raw
  result references are retained in Finding evidence;
- raw hit count is the number of SARIF result entries, even when a malformed item cannot normalize.

The Golden contract covers clean, findings, partial, malformed, and failed-execution states. The
opt-in real smoke fixture is an Apache-2.0 Java 17 Maven project and must produce a command-injection
path with both a real Source and Sink.
