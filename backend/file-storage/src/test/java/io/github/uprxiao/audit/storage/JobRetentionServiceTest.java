package io.github.uprxiao.audit.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.finding.FailureDetails;
import io.github.uprxiao.audit.finding.ScanJob;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import io.github.uprxiao.audit.finding.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JobRetentionServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-12T00:00:00Z");

    @TempDir
    Path dataRoot;

    @Test
    void appliesThirtyDaySuccessSevenDayFailureAndTwentyFourHourWorkspacePolicies() throws Exception {
        StoredScanJob recentFailure = failedJob(NOW.minus(Duration.ofDays(2)));
        StoredScanJob expiredFailure = failedJob(NOW.minus(Duration.ofDays(8)));
        StoredScanJob expiredSuccess = completedJob(NOW.minus(Duration.ofDays(31)));
        StoredScanJob running = runningJob(NOW.minus(Duration.ofDays(60)));
        JobDirectoryLayout recentLayout = createJob(recentFailure, "recent-workspace");
        JobDirectoryLayout expiredFailureLayout = createJob(expiredFailure, "old-failure");
        JobDirectoryLayout expiredSuccessLayout = createJob(expiredSuccess, "old-success");
        JobDirectoryLayout runningLayout = createJob(running, "running-workspace");
        RetentionPolicy policy = new RetentionPolicy(Duration.ofDays(30), Duration.ofDays(7),
                Duration.ofHours(24), 0);
        JobRetentionService service = new JobRetentionService(dataRoot, policy,
                new JobTemporaryFileCleaner(), ignored -> 1234);

        RetentionCleanupResult result = service.cleanExpired(
                List.of(recentFailure, expiredFailure, expiredSuccess, running), NOW);

        assertEquals(3, result.events().size());
        assertFalse(Files.exists(recentLayout.workspace()));
        assertTrue(Files.exists(recentLayout.report()));
        assertFalse(Files.exists(expiredFailureLayout.root()));
        assertFalse(Files.exists(expiredSuccessLayout.root()));
        assertTrue(Files.exists(runningLayout.workspace()));
    }

    @Test
    void lowDiskDeletesOnlyTerminalJobsInOldestFirstOrder() throws Exception {
        StoredScanJob oldest = completedJob(NOW.minusSeconds(30));
        StoredScanJob newest = completedJob(NOW.minusSeconds(10));
        StoredScanJob running = runningJob(NOW.minusSeconds(60));
        createJob(oldest, "123456");
        createJob(newest, "123456");
        JobDirectoryLayout runningLayout = createJob(running, "running");
        RetentionPolicy policy = new RetentionPolicy(Duration.ofDays(30), Duration.ofDays(7),
                Duration.ofHours(24), 10);
        AtomicInteger spaceChecks = new AtomicInteger();
        JobRetentionService service = new JobRetentionService(dataRoot, policy,
                new JobTemporaryFileCleaner(), ignored -> spaceChecks.incrementAndGet() >= 3 ? 20 : 0);

        RetentionCleanupResult result = service.cleanForLowDisk(List.of(newest, running, oldest));

        assertEquals(List.of(oldest.scanId(), newest.scanId()), result.events().stream()
                .map(RetentionCleanupResult.CleanupEvent::scanId).toList());
        assertTrue(result.usableBytesAfterCleanup() >= 10);
        assertTrue(Files.exists(runningLayout.root()));
    }

    @Test
    void guardedDeletionRejectsRunningStateAndSymbolicLinkRoots() throws Exception {
        StoredScanJob running = runningJob(NOW);
        JobDirectoryLayout layout = createJob(running, "content");
        JobTemporaryFileCleaner cleaner = new JobTemporaryFileCleaner();

        assertThrows(IllegalStateException.class, () -> cleaner.deleteTerminalJob(layout, running));

        Path separateData = Files.createDirectories(dataRoot.resolve("symlink-case"));
        UUID id = UUID.randomUUID();
        Path outside = Files.createDirectories(dataRoot.resolve("outside"));
        Path jobs = Files.createDirectories(separateData.resolve("jobs"));
        try {
            Files.createSymbolicLink(jobs.resolve(id.toString()), outside);
            JobDirectoryLayout linked = new JobDirectoryLayout(separateData, id);
            assertThrows(java.io.IOException.class, linked::initialize);
        } catch (UnsupportedOperationException exception) {
            // The V1 target platforms support symlinks; tolerate exotic test file systems.
        }
    }

    private JobDirectoryLayout createJob(StoredScanJob job, String content) throws Exception {
        JobDirectoryLayout layout = new JobDirectoryLayout(dataRoot, job.scanId());
        layout.initialize();
        Files.writeString(layout.workspace().resolve("content.bin"), content);
        Files.writeString(layout.report().resolve("report.json"), "{}");
        return layout;
    }

    private StoredScanJob completedJob(Instant completed) {
        ScanJob job = pathToRunning(completed.minusSeconds(4));
        job = job.transitionTo(ScanStatus.FINALIZING, completed.minusSeconds(1));
        return StoredScanJob.from(job.transitionTo(ScanStatus.COMPLETED, completed));
    }

    private StoredScanJob failedJob(Instant completed) {
        ScanJob job = pathToRunning(completed.minusSeconds(4));
        return StoredScanJob.from(job.transitionTo(ScanStatus.FAILED, completed,
                new FailureDetails("TEST_FAILURE", "test", Map.of())));
    }

    private StoredScanJob runningJob(Instant updated) {
        return StoredScanJob.from(pathToRunning(updated.minusSeconds(3)));
    }

    private ScanJob pathToRunning(Instant start) {
        ScanJob job = ScanJob.queued(UUID.randomUUID(), SourceType.ZIP, ScanProfile.QUICK, start);
        job = job.transitionTo(ScanStatus.ACQUIRING_SOURCE, start.plusSeconds(1));
        job = job.transitionTo(ScanStatus.PREFLIGHT, start.plusSeconds(2));
        return job.transitionTo(ScanStatus.RUNNING, start.plusSeconds(3));
    }
}
