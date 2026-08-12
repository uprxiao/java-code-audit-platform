package io.github.uprxiao.audit.scanner;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public record ExecutionSpec(
        EngineId engine,
        List<String> command,
        Path workingDirectory,
        Map<String, String> environment,
        Duration timeout,
        ResourceRequest resources,
        Set<ExpectedArtifact> expectedArtifacts,
        RedactionPolicy redactionPolicy) {

    public ExecutionSpec {
        Objects.requireNonNull(engine, "engine");
        command = command == null ? List.of() : List.copyOf(command);
        if (command.isEmpty() || command.stream().anyMatch(value -> value == null || value.isBlank())) {
            throw new IllegalArgumentException("command must contain an executable and non-blank arguments");
        }
        Objects.requireNonNull(workingDirectory, "workingDirectory");
        workingDirectory = workingDirectory.toAbsolutePath().normalize();
        environment = environment == null ? Map.of() : Map.copyOf(environment);
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        Objects.requireNonNull(resources, "resources");
        expectedArtifacts = expectedArtifacts == null ? Set.of() : Set.copyOf(expectedArtifacts);
        redactionPolicy = redactionPolicy == null ? RedactionPolicy.NONE : redactionPolicy;
    }
}
