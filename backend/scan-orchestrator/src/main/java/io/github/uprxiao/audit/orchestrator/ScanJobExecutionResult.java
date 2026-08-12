package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.scanner.EngineId;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record ScanJobExecutionResult(
        UUID scanId,
        Disposition disposition,
        Map<EngineId, EngineStatus> engines,
        Instant completedAt) {

    public enum Disposition {
        COMPLETED,
        COMPLETED_WITH_ERRORS,
        CANCELLED,
        DEFERRED_FOR_RESTART
    }

    public ScanJobExecutionResult {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(disposition, "disposition");
        engines = engines == null ? Map.of() : Map.copyOf(engines);
        Objects.requireNonNull(completedAt, "completedAt");
    }
}
