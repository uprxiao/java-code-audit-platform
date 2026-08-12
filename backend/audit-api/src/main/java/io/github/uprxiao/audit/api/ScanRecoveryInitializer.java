package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.EngineTaskState;
import io.github.uprxiao.audit.orchestrator.ScanRecoveryPolicy;
import io.github.uprxiao.audit.storage.JobRecoveryService;
import io.github.uprxiao.audit.storage.JobStore;
import io.github.uprxiao.audit.storage.SingleInstanceLock;
import io.github.uprxiao.audit.storage.StoredScanJob;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
final class ScanRecoveryInitializer {

    private final JobStore jobs;
    private final Clock clock;
    private final ScanRecoveryPolicy policy;
    private final StoredJobsLoader loader;

    @Autowired
    ScanRecoveryInitializer(
            JobStore jobs, Clock clock, AuditRuntimePaths paths, SingleInstanceLock instanceLock) {
        this(jobs, clock, new ScanRecoveryPolicy(), () ->
                new JobRecoveryService(paths.dataRoot()).recover().recovered());
        Objects.requireNonNull(instanceLock, "instanceLock");
    }

    ScanRecoveryInitializer(JobStore jobs, Clock clock) {
        this(jobs, clock, new ScanRecoveryPolicy(), jobs::list);
    }

    ScanRecoveryInitializer(
            JobStore jobs, Clock clock, ScanRecoveryPolicy policy, StoredJobsLoader loader) {
        this.jobs = Objects.requireNonNull(jobs, "jobs");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.loader = Objects.requireNonNull(loader, "loader");
    }

    @PostConstruct
    void recoverActiveJobs() throws IOException {
        for (StoredScanJob stored : loader.load()) {
            Instant observed = clock.instant();
            Instant recoveryTime = observed.isBefore(stored.updatedAt()) ? stored.updatedAt() : observed;
            ScanRecoveryPolicy.RecoveryDecision decision = policy.recover(stored.toScanJob(), recoveryTime);
            if (decision.action() != ScanRecoveryPolicy.RecoveryAction.MARK_INTERRUPTED) {
                continue;
            }
            jobs.save(StoredScanJob.from(
                    decision.job(), interruptedEngines(stored.engines(), recoveryTime), stored.artifacts()));
        }
    }

    private Map<String, EngineTaskState> interruptedEngines(
            Map<String, EngineTaskState> engines, Instant recoveryTime) {
        Map<String, EngineTaskState> result = new LinkedHashMap<>();
        engines.forEach((id, state) -> {
            EngineTaskState recovered = state;
            if (state.status() == EngineStatus.PENDING
                    || state.status() == EngineStatus.READY
                    || state.status() == EngineStatus.RUNNING) {
                Instant taskTime = recoveryTime.isBefore(state.updatedAt()) ? state.updatedAt() : recoveryTime;
                recovered = state.transitionTo(EngineStatus.CANCELLED, taskTime);
            }
            result.put(id, recovered);
        });
        return Map.copyOf(result);
    }

    @FunctionalInterface
    interface StoredJobsLoader {
        List<StoredScanJob> load() throws IOException;
    }
}
