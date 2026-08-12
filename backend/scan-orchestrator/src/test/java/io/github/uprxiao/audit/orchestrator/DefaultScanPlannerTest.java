package io.github.uprxiao.audit.orchestrator;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.finding.ScanProfile;
import org.junit.jupiter.api.Test;

class DefaultScanPlannerTest {

    private final DefaultScanPlanner planner = new DefaultScanPlanner();

    @Test
    void standardIncludesQuickAndBuildEngines() {
        ScanPlan plan = planner.plan(ScanProfile.STANDARD);

        assertTrue(plan.engines().contains(ScanEngine.GITLEAKS));
        assertTrue(plan.engines().contains(ScanEngine.SPOTBUGS));
        assertFalse(plan.engines().contains(ScanEngine.CODEQL));
    }

    @Test
    void deepIncludesCodeQl() {
        ScanPlan plan = planner.plan(ScanProfile.DEEP);

        assertTrue(plan.engines().contains(ScanEngine.CODEQL));
        assertFalse(plan.engines().stream().map(Enum::name).anyMatch("ERROR_PRONE"::equals));
        assertFalse(plan.engines().stream().map(Enum::name).anyMatch("NULLAWAY"::equals));
    }
}
