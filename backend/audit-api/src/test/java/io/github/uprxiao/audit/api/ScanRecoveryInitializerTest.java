package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.EngineTaskState;
import io.github.uprxiao.audit.finding.ScanJob;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import io.github.uprxiao.audit.finding.SourceType;
import io.github.uprxiao.audit.storage.JobStore;
import io.github.uprxiao.audit.storage.StoredScanJob;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ScanRecoveryInitializerTest {

    @Test
    void marksRunningJobAndNonTerminalEnginesInterruptedOnStartup() throws Exception {
        Instant created = Instant.parse("2026-08-12T00:00:00Z");
        ScanJob running = ScanJob.queued(UUID.randomUUID(), SourceType.ZIP, ScanProfile.STANDARD, created)
                .transitionTo(ScanStatus.ACQUIRING_SOURCE, created.plusSeconds(1))
                .transitionTo(ScanStatus.PREFLIGHT, created.plusSeconds(2))
                .transitionTo(ScanStatus.RUNNING, created.plusSeconds(3));
        EngineTaskState engine = EngineTaskState.pending("semgrep", created)
                .transitionTo(EngineStatus.READY, created.plusSeconds(2))
                .transitionTo(EngineStatus.RUNNING, created.plusSeconds(3));
        InMemoryJobStore store = new InMemoryJobStore(List.of(
                StoredScanJob.from(running, Map.of("semgrep", engine), Map.of("raw", "raw/semgrep"))));

        new ScanRecoveryInitializer(
                store, Clock.fixed(created.plusSeconds(10), ZoneOffset.UTC)).recoverActiveJobs();

        StoredScanJob recovered = store.find(running.id()).orElseThrow();
        assertEquals(ScanStatus.INTERRUPTED, recovered.status());
        assertEquals("SERVICE_RESTART_INTERRUPTED", recovered.failure().code());
        assertEquals(EngineStatus.CANCELLED, recovered.engines().get("semgrep").status());
        assertEquals("raw/semgrep", recovered.artifacts().get("raw"));
        assertEquals(running.revision() + 1, recovered.revision());
    }

    @Test
    void leavesQueuedAndTerminalJobsUnchangedForLaterIndexRecovery() throws Exception {
        Instant now = Instant.parse("2026-08-12T00:00:00Z");
        ScanJob queued = ScanJob.queued(UUID.randomUUID(), SourceType.ZIP, ScanProfile.QUICK, now);
        ScanJob completed = ScanJob.queued(UUID.randomUUID(), SourceType.ZIP, ScanProfile.QUICK, now)
                .transitionTo(ScanStatus.ACQUIRING_SOURCE, now.plusSeconds(1))
                .transitionTo(ScanStatus.PREFLIGHT, now.plusSeconds(2))
                .transitionTo(ScanStatus.RUNNING, now.plusSeconds(3))
                .transitionTo(ScanStatus.FINALIZING, now.plusSeconds(4))
                .transitionTo(ScanStatus.COMPLETED, now.plusSeconds(5));
        InMemoryJobStore store = new InMemoryJobStore(List.of(
                StoredScanJob.from(queued), StoredScanJob.from(completed)));

        new ScanRecoveryInitializer(store, Clock.fixed(now.plusSeconds(10), ZoneOffset.UTC)).recoverActiveJobs();

        assertEquals(ScanStatus.QUEUED, store.find(queued.id()).orElseThrow().status());
        assertEquals(ScanStatus.COMPLETED, store.find(completed.id()).orElseThrow().status());
        assertEquals(0, store.saveCount);
    }

    private static final class InMemoryJobStore implements JobStore {
        private final Map<UUID, StoredScanJob> jobs = new LinkedHashMap<>();
        private int saveCount;

        private InMemoryJobStore(List<StoredScanJob> initial) {
            initial.forEach(job -> jobs.put(job.scanId(), job));
        }

        @Override
        public void save(StoredScanJob job) {
            jobs.put(job.scanId(), job);
            saveCount++;
        }

        @Override
        public Optional<StoredScanJob> find(UUID scanId) {
            return Optional.ofNullable(jobs.get(scanId));
        }

        @Override
        public List<StoredScanJob> list() {
            return new ArrayList<>(jobs.values());
        }
    }
}
