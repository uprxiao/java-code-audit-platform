package io.github.uprxiao.audit.scanner;

import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;

public record RawArtifactSet(EngineId engine, Map<String, Path> artifacts, ExecutionResult execution) {

    public RawArtifactSet {
        Objects.requireNonNull(engine, "engine");
        artifacts = artifacts == null ? Map.of() : Map.copyOf(artifacts);
        Objects.requireNonNull(execution, "execution");
    }
}
