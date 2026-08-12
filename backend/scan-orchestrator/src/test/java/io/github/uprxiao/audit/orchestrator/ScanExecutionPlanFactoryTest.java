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
import java.util.Set;
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
                .allMatch(task -> task.toolPermits().equals(Set.of(ScanExecutionPlanFactory.MAVEN_TOOL_PERMIT))));
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

    @Test
    void mapsProcessFamiliesToSharedToolPermits() {
        ScanPlan plan = new ScanPlan(ScanProfile.DEEP, List.of(
                planned(ScanEngine.MAVEN_DEPENDENCY_ANALYSIS, true),
                planned(ScanEngine.MAVEN_ENFORCER, true),
                planned(ScanEngine.CYCLONEDX, true),
                planned(ScanEngine.DEPENDENCY_CHECK, true),
                planned(ScanEngine.CODEQL, true),
                planned(ScanEngine.SEMGREP, false)));
        Map<ScanEngine, EngineAction> actions = new java.util.EnumMap<>(ScanEngine.class);
        plan.plannedEngines().forEach(engine -> actions.put(engine.engine(), token -> EngineExecutionResult.succeeded()));

        ScheduledScanJob scheduled = factory.create(
                UUID.randomUUID(), plan, token -> EngineExecutionResult.succeeded(), actions);
        Map<io.github.uprxiao.audit.scanner.EngineId, Set<io.github.uprxiao.audit.scanner.EngineId>> permits =
                scheduled.engines().stream().collect(java.util.stream.Collectors.toMap(
                        ScheduledEngineTask::id, ScheduledEngineTask::toolPermits));

        assertEquals(Set.of(ScanExecutionPlanFactory.MAVEN_TOOL_PERMIT),
                permits.get(ScanEngine.MAVEN_DEPENDENCY_ANALYSIS.id()));
        assertEquals(Set.of(ScanExecutionPlanFactory.MAVEN_TOOL_PERMIT),
                permits.get(ScanEngine.MAVEN_ENFORCER.id()));
        assertEquals(Set.of(ScanExecutionPlanFactory.MAVEN_TOOL_PERMIT),
                permits.get(ScanEngine.CYCLONEDX.id()));
        assertEquals(Set.of(ScanExecutionPlanFactory.DEPENDENCY_CHECK_TOOL_PERMIT),
                permits.get(ScanEngine.DEPENDENCY_CHECK.id()));
        assertEquals(Set.of(ScanExecutionPlanFactory.CODEQL_TOOL_PERMIT,
                        ScanExecutionPlanFactory.MAVEN_TOOL_PERMIT),
                permits.get(ScanEngine.CODEQL.id()));
        assertEquals(Set.of(ScanEngine.SEMGREP.id()), permits.get(ScanEngine.SEMGREP.id()));
    }

    private PlannedEngine planned(ScanEngine engine, boolean build) {
        return new PlannedEngine(
                engine, build, ResourceClass.MEDIUM, 2, 1024, Duration.ofMinutes(5), List.of());
    }
}
