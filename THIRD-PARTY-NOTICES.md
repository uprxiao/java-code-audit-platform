# Third-party notices

## Distributed scanner tool packs

The release ZIP includes locally assembled, checksum-pinned scanner tool packs. Original license files and bundled dependency notices are preserved beside each tool:

- Semgrep 1.170.0 — LGPL-2.1-or-later — <https://pypi.org/project/semgrep/1.170.0/>
- Gitleaks 8.30.1 — MIT — <https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1>
- PMD 7.26.0 — BSD-style license plus bundled notices — <https://github.com/pmd/pmd/releases/tag/pmd_releases%2F7.26.0>
- Checkstyle 12.3.1 — LGPL-2.1-or-later — <https://github.com/checkstyle/checkstyle/releases/tag/checkstyle-12.3.1>
- Trivy 0.73.0 — Apache-2.0 — <https://github.com/aquasecurity/trivy/releases/tag/v0.73.0>
- SpotBugs 4.9.3 — LGPL-2.1-only plus bundled notices — <https://github.com/spotbugs/spotbugs/releases/tag/4.9.3>
- FindSecBugs 1.14.0 — LGPL-3.0-only — <https://github.com/find-sec-bugs/find-sec-bugs/releases/tag/version-1.14.0>
- Dependency-Check 12.2.2 — Apache-2.0 — <https://github.com/dependency-check/DependencyCheck/releases/tag/v12.2.2>
- OSV-Scanner 2.3.8 — Apache-2.0 — <https://github.com/google/osv-scanner/releases/tag/v2.3.8>

CycloneDX Maven Plugin, Maven Dependency Plugin and Maven Enforcer Plugin are resolved by the deployment machine's system Maven from fixed coordinates; their binaries and the Maven cache are not redistributed in the ZIP. GitHub CodeQL CLI is also not redistributed.

## SVNKit 1.10.13

- Project: <https://svnkit.com/>
- Source: <https://svn.svnkit.com/repos/svnkit/tags/1.10.13/>
- Maven coordinate: `com.tmatesoft.svnkit:svnkit:1.10.13`

The complete source code for Java Code Audit Platform is available at <https://github.com/uprxiao/java-code-audit-platform> under the Apache License 2.0. SVNKit's own source is available from the source link above.

### The TMate License

This license applies to all portions of TMate SVNKit library, which are not externally-maintained libraries (e.g. Trilead SSH library).

All the source code and compiled classes in package `org.tigris.subversion.javahl` except `SvnClient` class are covered by the license in `JAVAHL-LICENSE` file.

Copyright (c) 2004-2025 TMate Software. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
- Redistributions in any form must be accompanied by information on how to obtain complete source code for the software that uses SVNKit and any accompanying software that uses the software that uses SVNKit. The source code must either be included in the distribution or be available for no more than the cost of distribution plus a nominal fee, and must be freely redistributable under reasonable conditions. For an executable file, complete source code means the source code for all modules it contains. It does not include source code for modules or files that typically accompany the major components of the operating system on which the executable file runs.
- Redistribution in any form without redistributing source code for software that uses SVNKit is possible only when such redistribution is explicitly permitted by TMate Software. Please contact TMate Software at support@svnkit.com to get such permission.

THIS SOFTWARE IS PROVIDED BY TMATE SOFTWARE "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE DISCLAIMED.

IN NO EVENT SHALL TMATE SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## LZ4 Java 1.11.2

- Project and source: <https://github.com/yawkat/lz4-java/tree/v1.11.2>
- Maven coordinate: `at.yawk.lz4:lz4-java:1.11.2`
- License: Apache License 2.0

This maintained, package-compatible fork replaces SVNKit's old
`org.lz4:lz4-java` transitive dependency. Its Apache License 2.0 text is
available at <https://www.apache.org/licenses/LICENSE-2.0>.
