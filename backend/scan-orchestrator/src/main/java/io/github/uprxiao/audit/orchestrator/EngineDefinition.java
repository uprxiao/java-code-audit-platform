package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.scanner.ResourceClass;
import java.util.List;

public record EngineDefinition(
        String id,
        boolean requiresBuild,
        ResourceClass resourceClass,
        int weight,
        int memoryMb,
        long timeoutSeconds,
        List<String> dependsOn) {

    public EngineDefinition {
        dependsOn = dependsOn == null ? List.of() : List.copyOf(dependsOn);
    }
}
