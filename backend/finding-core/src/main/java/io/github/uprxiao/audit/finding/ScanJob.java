package io.github.uprxiao.audit.finding;

import java.time.Instant;
import java.util.UUID;

public record ScanJob(
        UUID id,
        SourceType sourceType,
        ScanProfile profile,
        ScanStatus status,
        Instant createdAt) {

    public static ScanJob queued(SourceType sourceType, ScanProfile profile) {
        return new ScanJob(UUID.randomUUID(), sourceType, profile, ScanStatus.QUEUED, Instant.now());
    }
}
