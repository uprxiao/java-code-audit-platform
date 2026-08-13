# CodeQL V1 query policy

V1 does not copy or fork GitHub's CodeQL queries. Deep uses the locally installed, version-pinned
suite:

```text
codeql/java-queries@1.11.7/codeql-suites/java-code-scanning.qls
```

This suite supplies Java security path queries (including injection families) and frozen quality
queries (including correctness, nullness, resource, concurrency, and maintainability checks).
The adapter records the original query ID and tags and maps them to the platform's stable
`IssueCategory`, `RuleFamily`, severity, confidence, CWE, fingerprint, and data-flow model.

Upgrading the query pack requires updating `tools/manifest/codeql-local.yaml`, regenerating all five
Golden states, reviewing SARIF schema/metadata changes, and completing real Mac ARM64 and Linux
x86_64 Deep smoke tests.
