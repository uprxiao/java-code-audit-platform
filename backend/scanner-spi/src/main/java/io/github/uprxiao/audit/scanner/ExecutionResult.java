package io.github.uprxiao.audit.scanner;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

public record ExecutionResult(
        Status status,
        Integer exitCode,
        Instant startedAt,
        Instant completedAt,
        Duration duration,
        long processId,
        Path stdout,
        Path stderr,
        boolean stdoutTruncated,
        boolean stderrTruncated,
        String message) {

    public enum Status {
        SUCCEEDED,
        FAILED,
        TIMED_OUT,
        CANCELLED
    }

    public ExecutionResult {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(startedAt, "startedAt");
        Objects.requireNonNull(completedAt, "completedAt");
        if (completedAt.isBefore(startedAt)) {
            throw new IllegalArgumentException("completion cannot precede start");
        }
        duration = duration == null ? Duration.between(startedAt, completedAt) : duration;
        if (processId < 1) {
            throw new IllegalArgumentException("processId must be positive");
        }
        Objects.requireNonNull(stdout, "stdout");
        Objects.requireNonNull(stderr, "stderr");
        message = message == null ? "" : message;
        if (status == Status.SUCCEEDED && (exitCode == null || exitCode != 0)) {
            throw new IllegalArgumentException("successful execution requires exit code zero");
        }
    }
}
