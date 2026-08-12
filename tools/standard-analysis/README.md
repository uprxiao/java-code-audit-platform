# Standard Track 1 tool inputs

This directory contains reviewable metadata only. Binary distributions and Maven repositories remain under the
gitignored `tools/downloads/` tree.

- `scripts/build-standard-analysis-pack.sh` downloads pinned official SpotBugs 4.9.3 and FindSecBugs 1.14.0
  archives, verifies their SHA-256 values, and assembles the common Java tool pack.
- `scripts/run-standard-analysis-smoke.sh` runs the four real macOS/JDK 17 scanner smoke tests.
- Maven Dependency Plugin 3.9.0 and Maven Enforcer Plugin 3.6.2 are resolved by the pre-installed Maven into the
  server-controlled local repository. Their fully-qualified goals and parameters are fixed in the adapters.

SpotBugs and FindSecBugs are a shared execution group: one SpotBugs XML report contains core and `SECURITY`
FindSecBugs bug instances. The two logical adapters partition that report without duplicating raw hits.
