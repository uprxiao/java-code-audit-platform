package io.github.uprxiao.audit.storage;

import io.github.uprxiao.audit.finding.EngineTaskState;
import io.github.uprxiao.audit.finding.FailureDetails;
import io.github.uprxiao.audit.finding.ScanJob;
import io.github.uprxiao.audit.finding.ScanPhase;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import io.github.uprxiao.audit.finding.SourceType;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record StoredScanJob(
        int schemaVersion,
        UUID scanId,
        long revision,
        SourceType sourceType,
        ScanProfile profile,
        ScanStatus status,
        ScanPhase phase,
        Instant createdAt,
        Instant updatedAt,
        Instant startedAt,
        Instant completedAt,
        boolean terminal,
        Map<String, EngineTaskState> engines,
        Map<String, String> artifacts,
        FailureDetails failure) {

    public StoredScanJob {
        if (schemaVersion != ScanJob.CURRENT_SCHEMA_VERSION) {
            throw new IllegalArgumentException("unsupported stored job schemaVersion: " + schemaVersion);
        }
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(status, "status");
        if (terminal != status.isTerminal()) {
            throw new IllegalArgumentException("terminal flag must match status");
        }
        engines = engines == null ? Map.of() : Map.copyOf(engines);
        artifacts = artifacts == null ? Map.of() : Map.copyOf(artifacts);
        new ScanJob(schemaVersion, scanId, revision, sourceType, profile, status, phase,
                createdAt, updatedAt, startedAt, completedAt, failure);
    }

    public static StoredScanJob from(ScanJob job) {
        return from(job, Map.of(), Map.of());
    }

    public static StoredScanJob from(
            ScanJob job, Map<String, EngineTaskState> engines, Map<String, String> artifacts) {
        Objects.requireNonNull(job, "job");
        return new StoredScanJob(job.schemaVersion(), job.id(), job.revision(), job.sourceType(), job.profile(),
                job.status(), job.phase(), job.createdAt(), job.updatedAt(), job.startedAt(), job.completedAt(),
                job.status().isTerminal(), engines, artifacts, job.failure());
    }

    public ScanJob toScanJob() {
        return new ScanJob(schemaVersion, scanId, revision, sourceType, profile, status, phase,
                createdAt, updatedAt, startedAt, completedAt, failure);
    }
}
