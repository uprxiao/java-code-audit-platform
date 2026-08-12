package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.scanner.EngineId;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public final class ScanExecutionPlanFactory {

    public static final EngineId MAVEN_BUILD = new EngineId("maven-build");
    public static final EngineId MAVEN_TOOL_PERMIT = new EngineId("maven");

    public ScheduledScanJob create(
            UUID scanId,
            ScanPlan plan,
            EngineAction mavenBuild,
            Map<ScanEngine, EngineAction> actions,
            ScanJobListener listener) {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(actions, "actions");
        boolean requiresBuild = plan.plannedEngines().stream().anyMatch(PlannedEngine::requiresBuild);
        if (requiresBuild) {
            Objects.requireNonNull(mavenBuild, "mavenBuild");
        }
        List<ScheduledEngineTask> tasks = new ArrayList<>();
        if (requiresBuild) {
            tasks.add(new ScheduledEngineTask(
                    MAVEN_BUILD, Set.of(), 4, MAVEN_TOOL_PERMIT, mavenBuild));
        }
        for (PlannedEngine engine : plan.plannedEngines()) {
            EngineAction action = actions.get(engine.engine());
            if (action == null) {
                throw new IllegalArgumentException("missing action for planned engine " + engine.engine().id());
            }
            Set<EngineId> dependencies = new LinkedHashSet<>();
            engine.dependsOn().stream().map(ScanEngine::id).forEach(dependencies::add);
            if (engine.requiresBuild()) {
                dependencies.add(MAVEN_BUILD);
            }
            tasks.add(new ScheduledEngineTask(
                    engine.engine().id(), dependencies, engine.weight(), engine.engine().id(), action));
        }
        return new ScheduledScanJob(scanId, tasks, listener);
    }

    public ScheduledScanJob create(
            UUID scanId,
            ScanPlan plan,
            EngineAction mavenBuild,
            Map<ScanEngine, EngineAction> actions) {
        return create(scanId, plan, mavenBuild, actions, ScanJobListener.NONE);
    }
}
