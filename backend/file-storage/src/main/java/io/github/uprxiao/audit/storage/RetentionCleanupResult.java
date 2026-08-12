package io.github.uprxiao.audit.storage;

import java.util.List;
import java.util.UUID;

public record RetentionCleanupResult(List<CleanupEvent> events, long usableBytesAfterCleanup) {
    public RetentionCleanupResult {
        events = List.copyOf(events);
    }

    public record CleanupEvent(UUID scanId, Scope scope, String reason, long reclaimedBytes) {
    }

    public enum Scope {
        TEMPORARY_WORKSPACE,
        ENTIRE_JOB
    }
}
