package io.github.uprxiao.audit.scanner;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record ToolProbeRequest(
        EngineId engine,
        Path executable,
        List<String> versionArguments,
        Path workingDirectory,
        Map<String, String> environment,
        Duration timeout) {

    public ToolProbeRequest {
        Objects.requireNonNull(engine, "engine");
        Objects.requireNonNull(executable, "executable");
        executable = executable.toAbsolutePath().normalize();
        versionArguments = versionArguments == null ? List.of() : List.copyOf(versionArguments);
        Objects.requireNonNull(workingDirectory, "workingDirectory");
        workingDirectory = workingDirectory.toAbsolutePath().normalize();
        environment = environment == null ? Map.of() : Map.copyOf(environment);
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("probe timeout must be positive");
        }
    }
}
