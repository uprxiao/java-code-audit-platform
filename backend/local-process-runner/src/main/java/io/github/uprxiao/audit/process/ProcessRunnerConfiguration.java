package io.github.uprxiao.audit.process;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;

public record ProcessRunnerConfiguration(
        long maxLogBytes,
        Duration pollInterval,
        Duration gracefulTermination,
        Set<String> allowedSystemCommands,
        Set<String> allowedEnvironmentKeys) {

    public static ProcessRunnerConfiguration defaults() {
        return new ProcessRunnerConfiguration(
                10L * 1024 * 1024,
                Duration.ofMillis(100),
                Duration.ofSeconds(2),
                Set.of("java", "mvn", "svn"),
                Set.of("PATH", "LANG", "LC_ALL", "HOME", "TMPDIR", "JAVA_HOME", "MAVEN_OPTS",
                        "SVN_USERNAME", "SVN_PASSWORD", "PYTHONDONTWRITEBYTECODE"));
    }

    public ProcessRunnerConfiguration {
        if (maxLogBytes < 1) {
            throw new IllegalArgumentException("maxLogBytes must be positive");
        }
        Objects.requireNonNull(pollInterval, "pollInterval");
        Objects.requireNonNull(gracefulTermination, "gracefulTermination");
        if (pollInterval.isZero() || pollInterval.isNegative()
                || gracefulTermination.isNegative()) {
            throw new IllegalArgumentException("process durations must be valid");
        }
        allowedSystemCommands = allowedSystemCommands == null ? Set.of() : Set.copyOf(allowedSystemCommands);
        allowedEnvironmentKeys = allowedEnvironmentKeys == null ? Set.of() : Set.copyOf(allowedEnvironmentKeys);
    }
}
