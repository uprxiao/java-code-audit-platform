package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.scanner.ResourceClass;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

public record PlannedEngine(
        ScanEngine engine,
        boolean requiresBuild,
        ResourceClass resourceClass,
        int weight,
        int memoryMb,
        Duration timeout,
        List<ScanEngine> dependsOn) {

    public PlannedEngine {
        Objects.requireNonNull(engine, "engine");
        Objects.requireNonNull(resourceClass, "resourceClass");
        Objects.requireNonNull(timeout, "timeout");
        dependsOn = dependsOn == null ? List.of() : List.copyOf(dependsOn);
        if (weight < 1 || memoryMb < 1 || timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("invalid engine resource configuration: " + engine);
        }
    }
}
