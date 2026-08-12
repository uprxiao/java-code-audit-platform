package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.scanner.EngineId;
import java.util.Arrays;

public enum ScanEngine {
    GITLEAKS("gitleaks"),
    SEMGREP("semgrep"),
    PMD("pmd"),
    PMD_CPD("pmd-cpd"),
    CHECKSTYLE("checkstyle"),
    TRIVY_REPOSITORY("trivy-repository"),
    SPOTBUGS("spotbugs"),
    FINDSECBUGS("findsecbugs"),
    DEPENDENCY_CHECK("dependency-check"),
    OSV_SCANNER("osv-scanner"),
    MAVEN_DEPENDENCY_ANALYSIS("maven-dependency-analysis"),
    MAVEN_ENFORCER("maven-enforcer"),
    CYCLONEDX("cyclonedx"),
    TRIVY_ARTIFACT("trivy-artifact"),
    CODEQL("codeql");

    private final EngineId id;

    ScanEngine(String id) {
        this.id = new EngineId(id);
    }

    public EngineId id() {
        return id;
    }

    public static ScanEngine fromId(EngineId id) {
        return Arrays.stream(values())
                .filter(engine -> engine.id.equals(id))
                .findFirst()
                .orElseThrow(() -> new ProfileConfigurationException("unknown V1 engine: " + id));
    }
}
