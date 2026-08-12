package io.github.uprxiao.audit.process;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

public record MavenBuildRequest(
        Path projectRoot,
        Path engineOutputDirectory,
        List<String> profiles,
        Map<String, String> properties,
        Duration timeout) {

    public MavenBuildRequest {
        projectRoot = normalize(projectRoot, "projectRoot");
        if (!Files.isRegularFile(projectRoot.resolve("pom.xml"))) {
            throw new IllegalArgumentException("Maven project root must contain pom.xml: " + projectRoot);
        }
        engineOutputDirectory = normalize(engineOutputDirectory, "engineOutputDirectory");
        profiles = profiles == null ? List.of() : List.copyOf(profiles);
        properties = properties == null
                ? Map.of()
                : Collections.unmodifiableMap(new TreeMap<>(properties));
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("Maven timeout must be positive");
        }
    }

    private static Path normalize(Path value, String name) {
        return Objects.requireNonNull(value, name).toAbsolutePath().normalize();
    }
}
