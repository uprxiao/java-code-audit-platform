package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.FailureDetails;
import io.github.uprxiao.audit.finding.ScanJob;
import io.github.uprxiao.audit.finding.ScanStatus;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

public final class ScanRecoveryPolicy {

    public RecoveryDecision recover(ScanJob persisted, Instant now) {
        Objects.requireNonNull(persisted, "persisted");
        Objects.requireNonNull(now, "now");
        if (persisted.status() == ScanStatus.QUEUED) {
            return new RecoveryDecision(RecoveryAction.REQUEUE, persisted);
        }
        if (persisted.status().isTerminal()) {
            return new RecoveryDecision(RecoveryAction.RESTORE_QUERY_ONLY, persisted);
        }
        ScanJob interrupted = persisted.transitionTo(
                ScanStatus.INTERRUPTED,
                now,
                new FailureDetails(
                        "SERVICE_RESTART_INTERRUPTED",
                        "scan was active when the service restarted and will not be resumed automatically",
                        Map.of("previousStatus", persisted.status().name())));
        return new RecoveryDecision(RecoveryAction.MARK_INTERRUPTED, interrupted);
    }

    public enum RecoveryAction {
        REQUEUE,
        MARK_INTERRUPTED,
        RESTORE_QUERY_ONLY
    }

    public record RecoveryDecision(RecoveryAction action, ScanJob job) {
        public RecoveryDecision {
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(job, "job");
        }
    }
}
