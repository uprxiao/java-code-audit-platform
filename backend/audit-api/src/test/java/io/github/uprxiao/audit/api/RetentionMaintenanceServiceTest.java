package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.github.uprxiao.audit.finding.ScanJob;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import io.github.uprxiao.audit.finding.SourceType;
import io.github.uprxiao.audit.storage.FileJobStore;
import io.github.uprxiao.audit.storage.JobDirectoryLayout;
import io.github.uprxiao.audit.storage.JobRetentionService;
import io.github.uprxiao.audit.storage.RetentionPolicy;
import io.github.uprxiao.audit.storage.StoredScanJob;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RetentionMaintenanceServiceTest {

    @TempDir
    Path dataRoot;

    @Test
    void startupMaintenanceRemovesExpiredTerminalJobsFromDisk() throws Exception {
        Instant now = Instant.parse("2026-08-12T00:00:00Z");
        ScanJob job = ScanJob.queued(UUID.randomUUID(), SourceType.ZIP, ScanProfile.QUICK,
                now.minus(Duration.ofDays(32)));
        job = job.transitionTo(ScanStatus.ACQUIRING_SOURCE, job.updatedAt().plusSeconds(1));
        job = job.transitionTo(ScanStatus.PREFLIGHT, job.updatedAt().plusSeconds(1));
        job = job.transitionTo(ScanStatus.RUNNING, job.updatedAt().plusSeconds(1));
        job = job.transitionTo(ScanStatus.FINALIZING, job.updatedAt().plusSeconds(1));
        job = job.transitionTo(ScanStatus.COMPLETED, job.updatedAt().plusSeconds(1));
        JobDirectoryLayout layout = new JobDirectoryLayout(dataRoot, job.id());
        layout.initialize();
        FileJobStore store = new FileJobStore(dataRoot);
        store.save(StoredScanJob.from(job));
        JobRetentionService retention = new JobRetentionService(dataRoot,
                new RetentionPolicy(Duration.ofDays(30), Duration.ofDays(7), Duration.ofHours(24), 0));
        RetentionMaintenanceService maintenance = new RetentionMaintenanceService(
                store, retention, Clock.fixed(now, ZoneOffset.UTC), ignored -> { });

        maintenance.cleanAtStartup();

        assertFalse(Files.exists(layout.root()));
        assertEquals(1, maintenance.lastResult().events().size());
        assertEquals("", maintenance.lastError());
    }
}
