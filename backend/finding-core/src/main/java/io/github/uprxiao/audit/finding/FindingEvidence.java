package io.github.uprxiao.audit.finding;

import java.util.Map;
import java.util.Objects;

public record FindingEvidence(
        String engine,
        String engineVersion,
        String ruleId,
        String engineSeverity,
        String rawArtifact,
        String rawItemId,
        Map<String, Object> properties) {

    public FindingEvidence {
        engine = requireText(engine, "engine");
        engineVersion = requireText(engineVersion, "engineVersion");
        ruleId = requireText(ruleId, "ruleId");
        rawArtifact = ProjectPath.normalize(requireText(rawArtifact, "rawArtifact"));
        engineSeverity = engineSeverity == null ? "" : engineSeverity;
        rawItemId = rawItemId == null ? "" : rawItemId;
        properties = properties == null ? Map.of() : Map.copyOf(properties);
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
