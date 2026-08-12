package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.scanner.EngineId;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public record ScheduledScanJob(UUID scanId, List<ScheduledEngineTask> engines, ScanJobListener listener) {

    public ScheduledScanJob {
        Objects.requireNonNull(scanId, "scanId");
        engines = engines == null ? List.of() : List.copyOf(engines);
        if (engines.isEmpty()) {
            throw new IllegalArgumentException("scheduled scan must contain at least one engine");
        }
        listener = listener == null ? ScanJobListener.NONE : listener;
        validateDag(engines);
    }

    public ScheduledScanJob(UUID scanId, List<ScheduledEngineTask> engines) {
        this(scanId, engines, ScanJobListener.NONE);
    }

    private static void validateDag(List<ScheduledEngineTask> engines) {
        Map<EngineId, ScheduledEngineTask> byId = new HashMap<>();
        for (ScheduledEngineTask engine : engines) {
            if (byId.putIfAbsent(engine.id(), engine) != null) {
                throw new IllegalArgumentException("duplicate scheduled engine: " + engine.id());
            }
        }
        for (ScheduledEngineTask engine : engines) {
            for (EngineId dependency : engine.dependsOn()) {
                if (!byId.containsKey(dependency)) {
                    throw new IllegalArgumentException(engine.id() + " depends on unknown engine " + dependency);
                }
            }
        }
        Set<EngineId> visiting = new HashSet<>();
        Set<EngineId> complete = new HashSet<>();
        for (EngineId id : byId.keySet()) {
            visit(id, byId, visiting, complete);
        }
    }

    private static void visit(
            EngineId id,
            Map<EngineId, ScheduledEngineTask> byId,
            Set<EngineId> visiting,
            Set<EngineId> complete) {
        if (complete.contains(id)) {
            return;
        }
        if (!visiting.add(id)) {
            throw new IllegalArgumentException("scheduled engine dependency cycle at " + id);
        }
        for (EngineId dependency : byId.get(id).dependsOn()) {
            visit(dependency, byId, visiting, complete);
        }
        visiting.remove(id);
        complete.add(id);
    }
}
