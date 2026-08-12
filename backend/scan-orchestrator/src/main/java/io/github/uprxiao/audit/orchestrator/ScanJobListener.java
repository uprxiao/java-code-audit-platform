package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.FailureDetails;
import io.github.uprxiao.audit.scanner.EngineId;
import java.util.UUID;

public interface ScanJobListener {

    ScanJobListener NONE = new ScanJobListener() {
    };

    default void onJobStarted(UUID scanId) {
    }

    default void onEngineStateChanged(
            UUID scanId, EngineId engineId, EngineStatus status, FailureDetails failure) {
    }

    default void onJobFinished(ScanJobExecutionResult result) {
    }
}
