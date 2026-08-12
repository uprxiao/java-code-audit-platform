package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.scanner.EngineId;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

public record SchedulerConfiguration(
        int maxQueuedScanJobs,
        int maxConcurrentScanJobs,
        int maxConcurrentEngines,
        int maxEnginesPerScan,
        int weightedPermits,
        Map<EngineId, Integer> toolLimits,
        Duration retryAfter) {

    public static SchedulerConfiguration defaults() {
        return new SchedulerConfiguration(
                20, 2, 4, 2, 8,
                Map.of(new EngineId("maven"), 1,
                        new EngineId("dependency-check"), 1,
                        new EngineId("codeql"), 1),
                Duration.ofSeconds(30));
    }

    public SchedulerConfiguration {
        if (maxQueuedScanJobs < 1 || maxConcurrentScanJobs < 1 || maxConcurrentEngines < 1
                || maxEnginesPerScan < 1 || weightedPermits < 1) {
            throw new IllegalArgumentException("scheduler limits must be positive");
        }
        if (maxEnginesPerScan > maxConcurrentEngines) {
            throw new IllegalArgumentException("per-scan engine limit cannot exceed global limit");
        }
        toolLimits = toolLimits == null ? Map.of() : Map.copyOf(toolLimits);
        for (Map.Entry<EngineId, Integer> entry : toolLimits.entrySet()) {
            Objects.requireNonNull(entry.getKey(), "tool limit id");
            if (entry.getValue() == null || entry.getValue() < 1
                    || entry.getValue() > maxConcurrentEngines) {
                throw new IllegalArgumentException("invalid tool limit for " + entry.getKey());
            }
        }
        Objects.requireNonNull(retryAfter, "retryAfter");
        if (retryAfter.isZero() || retryAfter.isNegative()) {
            throw new IllegalArgumentException("retryAfter must be positive");
        }
    }
}
