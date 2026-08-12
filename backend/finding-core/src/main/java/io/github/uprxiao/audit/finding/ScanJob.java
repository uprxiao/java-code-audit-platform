package io.github.uprxiao.audit.finding;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public record ScanJob(
        int schemaVersion,
        UUID id,
        long revision,
        SourceType sourceType,
        ScanProfile profile,
        ScanStatus status,
        ScanPhase phase,
        Instant createdAt,
        Instant updatedAt,
        Instant startedAt,
        Instant completedAt,
        FailureDetails failure) {

    public static final int CURRENT_SCHEMA_VERSION = 1;

    private static final Map<ScanStatus, Set<ScanStatus>> TRANSITIONS = Map.of(
            ScanStatus.QUEUED, Set.of(ScanStatus.ACQUIRING_SOURCE, ScanStatus.CANCELLED, ScanStatus.INTERRUPTED),
            ScanStatus.ACQUIRING_SOURCE, Set.of(ScanStatus.PREFLIGHT, ScanStatus.FAILED, ScanStatus.CANCELLED, ScanStatus.INTERRUPTED),
            ScanStatus.PREFLIGHT, Set.of(ScanStatus.RUNNING, ScanStatus.FAILED, ScanStatus.CANCELLED, ScanStatus.INTERRUPTED),
            ScanStatus.RUNNING, Set.of(ScanStatus.FINALIZING, ScanStatus.FAILED, ScanStatus.CANCELLED, ScanStatus.INTERRUPTED),
            ScanStatus.FINALIZING, Set.of(ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS, ScanStatus.FAILED,
                    ScanStatus.CANCELLED, ScanStatus.INTERRUPTED),
            ScanStatus.COMPLETED, Set.of(),
            ScanStatus.COMPLETED_WITH_ERRORS, Set.of(),
            ScanStatus.FAILED, Set.of(),
            ScanStatus.CANCELLED, Set.of(),
            ScanStatus.INTERRUPTED, Set.of());

    public ScanJob {
        if (schemaVersion != CURRENT_SCHEMA_VERSION) {
            throw new IllegalArgumentException("unsupported ScanJob schemaVersion: " + schemaVersion);
        }
        Objects.requireNonNull(id, "id");
        if (revision < 0) {
            throw new IllegalArgumentException("revision must be non-negative");
        }
        Objects.requireNonNull(sourceType, "sourceType");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(phase, "phase");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException("updatedAt must not be before createdAt");
        }
        if (phase != ScanPhase.forStatus(status)) {
            throw new IllegalArgumentException("phase does not match status");
        }
        if (status.isTerminal() != (completedAt != null)) {
            throw new IllegalArgumentException("terminal status and completedAt must agree");
        }
        if (failure != null && status != ScanStatus.FAILED && status != ScanStatus.INTERRUPTED
                && status != ScanStatus.COMPLETED_WITH_ERRORS) {
            throw new IllegalArgumentException("failure is only valid for failed, interrupted, or partial completion");
        }
    }

    public static ScanJob queued(SourceType sourceType, ScanProfile profile) {
        return queued(UUID.randomUUID(), sourceType, profile, Instant.now());
    }

    public static ScanJob queued(UUID id, SourceType sourceType, ScanProfile profile, Instant now) {
        return new ScanJob(CURRENT_SCHEMA_VERSION, id, 0, sourceType, profile, ScanStatus.QUEUED,
                ScanPhase.ACCEPTED, now, now, null, null, null);
    }

    public ScanJob transitionTo(ScanStatus next, Instant now) {
        return transitionTo(next, now, null);
    }

    public ScanJob transitionTo(ScanStatus next, Instant now, FailureDetails nextFailure) {
        Objects.requireNonNull(next, "next");
        Objects.requireNonNull(now, "now");
        if (!TRANSITIONS.get(status).contains(next)) {
            throw new IllegalStateException("illegal ScanJob transition: " + status + " -> " + next);
        }
        if (now.isBefore(updatedAt)) {
            throw new IllegalArgumentException("transition time must not go backwards");
        }
        if ((next == ScanStatus.FAILED || next == ScanStatus.INTERRUPTED || next == ScanStatus.COMPLETED_WITH_ERRORS)
                && nextFailure == null) {
            throw new IllegalArgumentException(next + " requires failure details");
        }
        Instant nextStartedAt = startedAt;
        if (nextStartedAt == null && next != ScanStatus.CANCELLED && next != ScanStatus.INTERRUPTED) {
            nextStartedAt = now;
        }
        Instant nextCompletedAt = next.isTerminal() ? now : null;
        return new ScanJob(schemaVersion, id, revision + 1, sourceType, profile, next,
                ScanPhase.forStatus(next), createdAt, now, nextStartedAt, nextCompletedAt, nextFailure);
    }
}
