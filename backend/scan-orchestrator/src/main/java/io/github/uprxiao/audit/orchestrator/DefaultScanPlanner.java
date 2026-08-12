package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.ScanProfile;
import java.util.ArrayList;
import java.util.List;

public final class DefaultScanPlanner {

    private static final List<ScanEngine> QUICK_ENGINES = List.of(
            ScanEngine.GITLEAKS,
            ScanEngine.SEMGREP,
            ScanEngine.PMD,
            ScanEngine.PMD_CPD,
            ScanEngine.CHECKSTYLE,
            ScanEngine.TRIVY_REPOSITORY);

    private static final List<ScanEngine> STANDARD_ENGINES = List.of(
            ScanEngine.SPOTBUGS,
            ScanEngine.FINDSECBUGS,
            ScanEngine.DEPENDENCY_CHECK,
            ScanEngine.OSV_SCANNER,
            ScanEngine.MAVEN_DEPENDENCY_ANALYSIS,
            ScanEngine.MAVEN_ENFORCER,
            ScanEngine.CYCLONEDX,
            ScanEngine.TRIVY_ARTIFACT);

    private static final List<ScanEngine> DEEP_ENGINES = List.of(ScanEngine.CODEQL);

    public ScanPlan plan(ScanProfile profile) {
        List<ScanEngine> engines = new ArrayList<>(QUICK_ENGINES);
        if (profile == ScanProfile.STANDARD || profile == ScanProfile.DEEP) {
            engines.addAll(STANDARD_ENGINES);
        }
        if (profile == ScanProfile.DEEP) {
            engines.addAll(DEEP_ENGINES);
        }
        return new ScanPlan(profile, engines);
    }
}
