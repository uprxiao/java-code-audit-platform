package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.storage.JobRetentionService;
import io.github.uprxiao.audit.storage.JobStore;
import io.github.uprxiao.audit.storage.RetentionCleanupResult;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

@Service
final class RetentionMaintenanceService {

    private final JobStore jobs;
    private final JobRetentionService retention;
    private final Clock clock;
    private final java.util.function.Consumer<java.util.UUID> indexCleanup;
    private final AtomicReference<String> lastError = new AtomicReference<>("");
    private volatile RetentionCleanupResult lastResult = new RetentionCleanupResult(List.of(), 0);

    @Autowired
    RetentionMaintenanceService(JobStore jobs, JobRetentionService retention, Clock clock, ScanService scans) {
        this(jobs, retention, clock, scans::forget);
    }

    RetentionMaintenanceService(
            JobStore jobs,
            JobRetentionService retention,
            Clock clock,
            java.util.function.Consumer<java.util.UUID> indexCleanup) {
        this.jobs = jobs;
        this.retention = retention;
        this.clock = clock;
        this.indexCleanup = indexCleanup;
    }

    @PostConstruct
    void cleanAtStartup() {
        runMaintenance();
    }

    @Scheduled(fixedDelayString = "${audit.retention.cleanup-interval:1h}")
    void cleanPeriodically() {
        runMaintenance();
    }

    RetentionCleanupResult lastResult() {
        return lastResult;
    }

    String lastError() {
        return lastError.get();
    }

    private synchronized void runMaintenance() {
        try {
            RetentionCleanupResult expired = retention.cleanExpired(jobs.list(), clock.instant());
            RetentionCleanupResult lowDisk = retention.cleanForLowDisk(jobs.list());
            List<RetentionCleanupResult.CleanupEvent> events = new ArrayList<>(expired.events());
            events.addAll(lowDisk.events());
            events.stream()
                    .filter(event -> event.scope() == RetentionCleanupResult.Scope.ENTIRE_JOB)
                    .forEach(event -> indexCleanup.accept(event.scanId()));
            lastResult = new RetentionCleanupResult(events, lowDisk.usableBytesAfterCleanup());
            lastError.set("");
        } catch (IOException | RuntimeException exception) {
            lastError.set(exception.getClass().getSimpleName() + ": "
                    + (exception.getMessage() == null ? "maintenance failed" : exception.getMessage()));
        }
    }
}
