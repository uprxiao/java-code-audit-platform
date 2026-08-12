package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.scanner.EngineId;
import java.util.Objects;
import java.util.Set;

public record ScheduledEngineTask(
        EngineId id,
        Set<EngineId> dependsOn,
        int weight,
        EngineId toolPermit,
        DependencyFailurePolicy dependencyFailurePolicy,
        EngineAction action) {

    public ScheduledEngineTask {
        Objects.requireNonNull(id, "id");
        dependsOn = dependsOn == null ? Set.of() : Set.copyOf(dependsOn);
        if (dependsOn.contains(id)) {
            throw new IllegalArgumentException("engine cannot depend on itself: " + id);
        }
        if (weight < 1) {
            throw new IllegalArgumentException("engine weight must be positive");
        }
        toolPermit = toolPermit == null ? id : toolPermit;
        dependencyFailurePolicy = dependencyFailurePolicy == null
                ? DependencyFailurePolicy.SKIP
                : dependencyFailurePolicy;
        Objects.requireNonNull(action, "action");
    }

    public ScheduledEngineTask(
            EngineId id,
            Set<EngineId> dependsOn,
            int weight,
            EngineId toolPermit,
            EngineAction action) {
        this(id, dependsOn, weight, toolPermit, DependencyFailurePolicy.SKIP, action);
    }

    public ScheduledEngineTask(EngineId id, Set<EngineId> dependsOn, int weight, EngineAction action) {
        this(id, dependsOn, weight, id, DependencyFailurePolicy.SKIP, action);
    }
}
