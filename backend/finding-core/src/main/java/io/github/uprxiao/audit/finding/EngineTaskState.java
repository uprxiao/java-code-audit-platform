package io.github.uprxiao.audit.finding;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public record EngineTaskState(
        String engineId,
        long revision,
        EngineStatus status,
        Instant createdAt,
        Instant updatedAt,
        Instant startedAt,
        Instant completedAt,
        FailureDetails failure) {

    private static final Map<EngineStatus, Set<EngineStatus>> TRANSITIONS = Map.of(
            EngineStatus.PENDING, Set.of(EngineStatus.READY, EngineStatus.SKIPPED, EngineStatus.CANCELLED),
            EngineStatus.READY, Set.of(EngineStatus.RUNNING, EngineStatus.SKIPPED, EngineStatus.CANCELLED),
            EngineStatus.RUNNING, Set.of(EngineStatus.SUCCEEDED, EngineStatus.PARTIAL, EngineStatus.FAILED,
                    EngineStatus.TIMED_OUT, EngineStatus.CANCELLED),
            EngineStatus.SUCCEEDED, Set.of(),
            EngineStatus.PARTIAL, Set.of(),
            EngineStatus.FAILED, Set.of(),
            EngineStatus.TIMED_OUT, Set.of(),
            EngineStatus.SKIPPED, Set.of(),
            EngineStatus.CANCELLED, Set.of());

    public EngineTaskState {
        if (engineId == null || engineId.isBlank()) {
            throw new IllegalArgumentException("engineId must not be blank");
        }
        if (revision < 0) {
            throw new IllegalArgumentException("revision must be non-negative");
        }
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (status.isTerminal() != (completedAt != null)) {
            throw new IllegalArgumentException("terminal status and completedAt must agree");
        }
        if (failure != null && status != EngineStatus.PARTIAL && status != EngineStatus.FAILED
                && status != EngineStatus.TIMED_OUT && status != EngineStatus.SKIPPED) {
            throw new IllegalArgumentException("failure details are not valid for " + status);
        }
    }

    public static EngineTaskState pending(String engineId, Instant now) {
        return new EngineTaskState(engineId, 0, EngineStatus.PENDING, now, now, null, null, null);
    }

    public EngineTaskState transitionTo(EngineStatus next, Instant now, FailureDetails nextFailure) {
        if (!TRANSITIONS.get(status).contains(next)) {
            throw new IllegalStateException("illegal EngineTask transition: " + status + " -> " + next);
        }
        if (now.isBefore(updatedAt)) {
            throw new IllegalArgumentException("transition time must not go backwards");
        }
        if ((next == EngineStatus.PARTIAL || next == EngineStatus.FAILED || next == EngineStatus.TIMED_OUT
                || next == EngineStatus.SKIPPED) && nextFailure == null) {
            throw new IllegalArgumentException(next + " requires reason details");
        }
        Instant nextStartedAt = startedAt == null && next == EngineStatus.RUNNING ? now : startedAt;
        return new EngineTaskState(engineId, revision + 1, next, createdAt, now, nextStartedAt,
                next.isTerminal() ? now : null, nextFailure);
    }

    public EngineTaskState transitionTo(EngineStatus next, Instant now) {
        return transitionTo(next, now, null);
    }
}
