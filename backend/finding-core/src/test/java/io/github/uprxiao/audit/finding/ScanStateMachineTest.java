package io.github.uprxiao.audit.finding;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ScanStateMachineTest {

    private static final Instant T0 = Instant.parse("2026-08-12T00:00:00Z");

    @Test
    void scanJobFollowsTheCompleteHappyPathAndIncrementsRevision() {
        ScanJob job = ScanJob.queued(UUID.fromString("00000000-0000-0000-0000-000000000001"),
                SourceType.ZIP, ScanProfile.STANDARD, T0);
        job = job.transitionTo(ScanStatus.ACQUIRING_SOURCE, T0.plusSeconds(1));
        job = job.transitionTo(ScanStatus.PREFLIGHT, T0.plusSeconds(2));
        job = job.transitionTo(ScanStatus.RUNNING, T0.plusSeconds(3));
        job = job.transitionTo(ScanStatus.FINALIZING, T0.plusSeconds(4));
        job = job.transitionTo(ScanStatus.COMPLETED, T0.plusSeconds(5));

        assertEquals(5, job.revision());
        assertEquals(ScanPhase.TERMINAL, job.phase());
        assertTrue(job.status().isTerminal());
        assertEquals(T0.plusSeconds(1), job.startedAt());
    }

    @Test
    void scanJobRejectsSkippedPhaseAndFailureWithoutDetails() {
        ScanJob job = ScanJob.queued(UUID.randomUUID(), SourceType.SVN, ScanProfile.QUICK, T0);
        assertThrows(IllegalStateException.class, () -> job.transitionTo(ScanStatus.RUNNING, T0.plusSeconds(1)));
        ScanJob acquiring = job.transitionTo(ScanStatus.ACQUIRING_SOURCE, T0.plusSeconds(1));
        assertThrows(IllegalArgumentException.class,
                () -> acquiring.transitionTo(ScanStatus.FAILED, T0.plusSeconds(2)));
    }

    @Test
    void engineTaskRejectsTerminalMutationAndRequiresFailureReason() {
        EngineTaskState task = EngineTaskState.pending("semgrep", T0)
                .transitionTo(EngineStatus.READY, T0.plusSeconds(1))
                .transitionTo(EngineStatus.RUNNING, T0.plusSeconds(2))
                .transitionTo(EngineStatus.SUCCEEDED, T0.plusSeconds(3));
        assertEquals(3, task.revision());
        assertThrows(IllegalStateException.class,
                () -> task.transitionTo(EngineStatus.FAILED, T0.plusSeconds(4),
                        new FailureDetails("LATE_FAILURE", "late", Map.of())));

        EngineTaskState running = EngineTaskState.pending("pmd", T0)
                .transitionTo(EngineStatus.READY, T0.plusSeconds(1))
                .transitionTo(EngineStatus.RUNNING, T0.plusSeconds(2));
        assertThrows(IllegalArgumentException.class,
                () -> running.transitionTo(EngineStatus.TIMED_OUT, T0.plusSeconds(3)));
    }
}
