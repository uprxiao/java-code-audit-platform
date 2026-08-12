package io.github.uprxiao.audit.scanner;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

public record EngineDescriptor(
        EngineId id,
        String displayName,
        boolean requiresBuild,
        ResourceRequest resources,
        Duration defaultTimeout,
        Set<EngineId> dependsOn) {

    public EngineDescriptor {
        Objects.requireNonNull(id, "id");
        displayName = displayName == null || displayName.isBlank() ? id.value() : displayName;
        Objects.requireNonNull(resources, "resources");
        Objects.requireNonNull(defaultTimeout, "defaultTimeout");
        if (defaultTimeout.isZero() || defaultTimeout.isNegative()) {
            throw new IllegalArgumentException("default timeout must be positive");
        }
        dependsOn = dependsOn == null ? Set.of() : Set.copyOf(dependsOn);
        if (dependsOn.contains(id)) {
            throw new IllegalArgumentException("engine cannot depend on itself: " + id);
        }
    }
}
