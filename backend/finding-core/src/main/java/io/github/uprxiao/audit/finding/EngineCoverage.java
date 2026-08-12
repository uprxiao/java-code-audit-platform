package io.github.uprxiao.audit.finding;

import java.time.Duration;
import java.util.Objects;

public record EngineCoverage(
        String engine,
        EngineStatus status,
        int modulesDiscovered,
        int modulesApplicable,
        int modulesScanned,
        long rawHitCount,
        Duration duration,
        String reasonCode,
        String artifact) {

    public EngineCoverage {
        Objects.requireNonNull(engine, "engine");
        Objects.requireNonNull(status, "status");
        if (modulesDiscovered < 0 || modulesApplicable < 0 || modulesScanned < 0 || rawHitCount < 0) {
            throw new IllegalArgumentException("coverage counts must be non-negative");
        }
        if (modulesScanned > modulesApplicable || modulesApplicable > modulesDiscovered) {
            throw new IllegalArgumentException("module coverage counts are inconsistent");
        }
        duration = duration == null ? Duration.ZERO : duration;
        reasonCode = reasonCode == null ? "" : reasonCode;
        artifact = artifact == null ? "" : artifact;
    }
}
