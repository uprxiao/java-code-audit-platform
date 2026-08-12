package io.github.uprxiao.audit.orchestrator;

public enum ScanEngine {
    GITLEAKS(false),
    SEMGREP(false),
    PMD(false),
    PMD_CPD(false),
    CHECKSTYLE(false),
    TRIVY_REPOSITORY(false),
    SPOTBUGS(true),
    FINDSECBUGS(true),
    DEPENDENCY_CHECK(true),
    OSV_SCANNER(true),
    MAVEN_DEPENDENCY_ANALYSIS(true),
    MAVEN_ENFORCER(true),
    CYCLONEDX(true),
    TRIVY_ARTIFACT(true),
    CODEQL(true);

    private final boolean requiresBuild;

    ScanEngine(boolean requiresBuild) {
        this.requiresBuild = requiresBuild;
    }

    public boolean requiresBuild() {
        return requiresBuild;
    }
}
