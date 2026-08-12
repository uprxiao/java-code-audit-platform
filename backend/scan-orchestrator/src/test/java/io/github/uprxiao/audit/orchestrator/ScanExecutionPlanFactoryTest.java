package io.github.uprxiao.audit.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.scanner.ResourceClass;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class ScanExecutionPlanFactoryTest {

    private final ScanExecutionPlanFactory factory = new ScanExecutionPlanFactory();

    @Test
    void insertsOneMavenBuildAndMakesOnlyBuildEnginesDependOnIt() throws Exception {
        ScanPlan plan = new ScanPlan(ScanProfile.STANDARD, List.of(
                planned(ScanEngine.SEMGREP, false),
                planned(ScanEngine.SPOTBUGS, true)));
        ScheduledScanJob scheduled = factory.create(
                UUID.randomUUID(),
                plan,
                token -> EngineExecutionResult.failed("MAVEN_BUILD_FAILED", "compile failed"),
                Map.of(
                        ScanEngine.SEMGREP, token -> EngineExecutionResult.succeeded(),
                        ScanEngine.SPOTBUGS, token -> EngineExecutionResult.succeeded()));

        assertEquals(3, scheduled.engines().size());
        assertTrue(scheduled.engines().stream()
                .filter(task -> task.id().equals(ScanExecutionPlanFactory.MAVEN_BUILD))
                .allMatch(task -> task.toolPermit().equals(ScanExecutionPlanFactory.MAVEN_TOOL_PERMIT)));
        try (FairDagScheduler scheduler = new FairDagScheduler(new SchedulerConfiguration(
                2, 1, 2, 2, 8,
                Map.of(ScanExecutionPlanFactory.MAVEN_TOOL_PERMIT, 1), Duration.ofSeconds(30)))) {
            ScanJobExecutionResult result = scheduler.submit(scheduled).completion().get(5, TimeUnit.SECONDS);
            assertEquals(EngineStatus.FAILED, result.engines().get(ScanExecutionPlanFactory.MAVEN_BUILD));
            assertEquals(EngineStatus.SUCCEEDED, result.engines().get(ScanEngine.SEMGREP.id()));
            assertEquals(EngineStatus.SKIPPED, result.engines().get(ScanEngine.SPOTBUGS.id()));
        }
    }

    @Test
    void failsBeforeAdmissionWhenAnyPlannedEngineHasNoAction() {
        ScanPlan plan = new ScanPlan(ScanProfile.QUICK, List.of(planned(ScanEngine.SEMGREP, false)));

        assertThrows(IllegalArgumentException.class,
                () -> factory.create(UUID.randomUUID(), plan, null, Map.of()));
    }

    private PlannedEngine planned(ScanEngine engine, boolean build) {
        return new PlannedEngine(
                engine, build, ResourceClass.MEDIUM, 2, 1024, Duration.ofMinutes(5), List.of());
    }
}
