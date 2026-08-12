package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.ScanProfile;
import java.util.List;
import java.util.Objects;

public final class ScanPlan {

    private final ScanProfile profile;
    private final List<PlannedEngine> plannedEngines;

    public ScanPlan(ScanProfile profile, List<PlannedEngine> plannedEngines) {
        this.profile = Objects.requireNonNull(profile, "profile");
        this.plannedEngines = List.copyOf(plannedEngines);
    }

    public ScanProfile profile() {
        return profile;
    }

    public List<PlannedEngine> plannedEngines() {
        return plannedEngines;
    }

    public List<ScanEngine> engines() {
        return plannedEngines.stream().map(PlannedEngine::engine).toList();
    }

    public int totalWeight() {
        return plannedEngines.stream().mapToInt(PlannedEngine::weight).sum();
    }
}
