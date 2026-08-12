package io.github.uprxiao.audit.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import io.github.uprxiao.audit.finding.ScanJob;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import io.github.uprxiao.audit.finding.SourceType;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ScanRecoveryPolicyTest {

    private final ScanRecoveryPolicy policy = new ScanRecoveryPolicy();
    private final Instant created = Instant.parse("2026-08-12T00:00:00Z");

    @Test
    void requeuesQueuedJobWithoutChangingRevision() {
        ScanJob queued = ScanJob.queued(UUID.randomUUID(), SourceType.ZIP, ScanProfile.QUICK, created);

        ScanRecoveryPolicy.RecoveryDecision result = policy.recover(queued, created.plusSeconds(5));

        assertEquals(ScanRecoveryPolicy.RecoveryAction.REQUEUE, result.action());
        assertSame(queued, result.job());
    }

    @Test
    void marksEveryActivePhaseInterruptedWithPreviousStateEvidence() {
        ScanJob job = ScanJob.queued(UUID.randomUUID(), SourceType.ZIP, ScanProfile.STANDARD, created);
        for (ScanStatus status : new ScanStatus[]{
                ScanStatus.ACQUIRING_SOURCE, ScanStatus.PREFLIGHT, ScanStatus.RUNNING, ScanStatus.FINALIZING}) {
            job = job.transitionTo(status, job.updatedAt().plus(1, ChronoUnit.SECONDS));
            ScanRecoveryPolicy.RecoveryDecision result = policy.recover(job, job.updatedAt().plusSeconds(1));
            assertEquals(ScanRecoveryPolicy.RecoveryAction.MARK_INTERRUPTED, result.action());
            assertEquals(ScanStatus.INTERRUPTED, result.job().status());
            assertEquals(status.name(), result.job().failure().details().get("previousStatus"));
            assertEquals(job.revision() + 1, result.job().revision());
        }
    }

    @Test
    void restoresTerminalJobForQueriesWithoutMutation() {
        ScanJob completed = ScanJob.queued(UUID.randomUUID(), SourceType.ZIP, ScanProfile.QUICK, created)
                .transitionTo(ScanStatus.ACQUIRING_SOURCE, created.plusSeconds(1))
                .transitionTo(ScanStatus.PREFLIGHT, created.plusSeconds(2))
                .transitionTo(ScanStatus.RUNNING, created.plusSeconds(3))
                .transitionTo(ScanStatus.FINALIZING, created.plusSeconds(4))
                .transitionTo(ScanStatus.COMPLETED, created.plusSeconds(5));

        ScanRecoveryPolicy.RecoveryDecision result = policy.recover(completed, created.plusSeconds(10));

        assertEquals(ScanRecoveryPolicy.RecoveryAction.RESTORE_QUERY_ONLY, result.action());
        assertSame(completed, result.job());
    }
}
