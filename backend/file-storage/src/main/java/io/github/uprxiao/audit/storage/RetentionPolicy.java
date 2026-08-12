package io.github.uprxiao.audit.storage;

import java.time.Duration;
import java.util.Objects;

public record RetentionPolicy(
        Duration successfulResults,
        Duration failedResults,
        Duration failedWorkspace,
        long minimumFreeBytes) {

    public static final long DEFAULT_MINIMUM_FREE_BYTES = 50L * 1024 * 1024 * 1024;

    public RetentionPolicy {
        successfulResults = positive(successfulResults, "successfulResults");
        failedResults = positive(failedResults, "failedResults");
        failedWorkspace = positive(failedWorkspace, "failedWorkspace");
        if (minimumFreeBytes < 0) {
            throw new IllegalArgumentException("minimumFreeBytes must be non-negative");
        }
    }

    public static RetentionPolicy defaults() {
        return new RetentionPolicy(Duration.ofDays(30), Duration.ofDays(7), Duration.ofHours(24),
                DEFAULT_MINIMUM_FREE_BYTES);
    }

    private static Duration positive(Duration value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return value;
    }
}
