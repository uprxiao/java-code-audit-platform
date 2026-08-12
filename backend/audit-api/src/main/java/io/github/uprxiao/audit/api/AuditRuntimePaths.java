package io.github.uprxiao.audit.api;

import java.nio.file.Path;

record AuditRuntimePaths(
        Path dataRoot,
        Path semgrepExecutable,
        Path semgrepRules,
        Path quickToolRoot,
        Path standardAnalysisToolRoot,
        Path codeqlExecutable,
        Path codeqlQuerySuite,
        Path gitleaksRules,
        Path pmdRules,
        Path checkstyleRules,
        Path spotbugsExcludeFilter) {

    AuditRuntimePaths(Path dataRoot, Path semgrepExecutable, Path semgrepRules) {
        this(dataRoot, semgrepExecutable, semgrepRules,
                Path.of("./tools/downloads/quick").toAbsolutePath().normalize(),
                Path.of("./tools/downloads/tool-pack/common/standard-analysis").toAbsolutePath().normalize(),
                Path.of("./tools/local/codeql-v2.26.2/codeql/codeql").toAbsolutePath().normalize(),
                Path.of("./tools/local/codeql-packs/codeql/java-queries/1.11.7/codeql-suites/java-security-and-quality.qls")
                        .toAbsolutePath().normalize(),
                Path.of("./config/rules/gitleaks/gitleaks.toml").toAbsolutePath().normalize(),
                Path.of("./config/rules/pmd/java-audit.xml").toAbsolutePath().normalize(),
                Path.of("./config/rules/checkstyle/java-audit.xml").toAbsolutePath().normalize(),
                Path.of("./config/rules/spotbugs-exclude.xml").toAbsolutePath().normalize());
    }

    Path gitleaksExecutable() {
        return quickToolRoot.resolve("gitleaks/bin/gitleaks");
    }

    Path pmdHome() {
        return quickToolRoot.resolve("pmd/home");
    }

    Path checkstyleJar() {
        return quickToolRoot.resolve("checkstyle/checkstyle-12.3.1-all.jar");
    }

    Path trivyExecutable() {
        return quickToolRoot.resolve("trivy/bin/trivy");
    }

    Path trivyCache() {
        return dataRoot.resolve("cache/trivy");
    }

    Path spotbugsHome() {
        return standardAnalysisToolRoot.resolve("spotbugs");
    }

    Path findSecBugsPlugin() {
        return standardAnalysisToolRoot.resolve("findsecbugs/lib/findsecbugs-plugin-1.14.0.jar");
    }

    Path mavenLocalRepository() {
        return dataRoot.resolve("cache/maven/repository");
    }

    Path javaExecutable() {
        return Path.of(System.getProperty("java.home"), "bin", "java").toAbsolutePath().normalize();
    }
}
