package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.ScanProfile;
import java.util.List;

public record ScanPlan(ScanProfile profile, List<ScanEngine> engines) {

    public ScanPlan {
        engines = List.copyOf(engines);
    }
}
