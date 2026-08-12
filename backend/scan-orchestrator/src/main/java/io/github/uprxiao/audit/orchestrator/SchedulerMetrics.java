package io.github.uprxiao.audit.orchestrator;

public record SchedulerMetrics(
        int queuedScanJobs,
        int queueCapacity,
        int activeScanJobs,
        int activeScanJobLimit,
        boolean accepting,
        EnginePermitManager.PermitSnapshot permits) {
}
