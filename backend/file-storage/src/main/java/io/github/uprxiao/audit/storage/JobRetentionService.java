package io.github.uprxiao.audit.storage;

import io.github.uprxiao.audit.finding.ScanStatus;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Applies configurable terminal-job retention and low-disk oldest-first cleanup. */
public final class JobRetentionService {

    private final Path dataRoot;
    private final RetentionPolicy policy;
    private final JobTemporaryFileCleaner cleaner;
    private final UsableSpaceProvider usableSpace;

    public JobRetentionService(Path dataRoot, RetentionPolicy policy) {
        this(dataRoot, policy, new JobTemporaryFileCleaner(), root -> Files.getFileStore(root).getUsableSpace());
    }

    JobRetentionService(
            Path dataRoot,
            RetentionPolicy policy,
            JobTemporaryFileCleaner cleaner,
            UsableSpaceProvider usableSpace) {
        this.dataRoot = Objects.requireNonNull(dataRoot, "dataRoot").toAbsolutePath().normalize();
        this.policy = Objects.requireNonNull(policy, "policy");
        this.cleaner = Objects.requireNonNull(cleaner, "cleaner");
        this.usableSpace = Objects.requireNonNull(usableSpace, "usableSpace");
    }

    public RetentionCleanupResult cleanExpired(List<StoredScanJob> jobs, Instant now) throws IOException {
        Objects.requireNonNull(now, "now");
        List<RetentionCleanupResult.CleanupEvent> events = new ArrayList<>();
        for (StoredScanJob job : terminalOldestFirst(jobs)) {
            JobDirectoryLayout layout = new JobDirectoryLayout(dataRoot, job.scanId());
            Instant completed = job.completedAt();
            if (completed.plus(resultRetention(job)).compareTo(now) <= 0) {
                long size = treeSize(layout.root());
                cleaner.deleteTerminalJob(layout, job);
                events.add(event(job.scanId(), RetentionCleanupResult.Scope.ENTIRE_JOB,
                        "RETENTION_EXPIRED", size));
            } else if (isFailure(job.status()) && completed.plus(policy.failedWorkspace()).compareTo(now) <= 0) {
                long before = temporarySize(layout);
                cleaner.cleanFailedJobWorkspace(layout);
                if (before > 0) {
                    events.add(event(job.scanId(), RetentionCleanupResult.Scope.TEMPORARY_WORKSPACE,
                            "FAILED_WORKSPACE_RETENTION_EXPIRED", before));
                }
            }
        }
        return new RetentionCleanupResult(events, usableSpace.usableBytes(dataRoot));
    }

    public RetentionCleanupResult cleanForLowDisk(List<StoredScanJob> jobs) throws IOException {
        long available = usableSpace.usableBytes(dataRoot);
        List<RetentionCleanupResult.CleanupEvent> events = new ArrayList<>();
        if (available >= policy.minimumFreeBytes()) {
            return new RetentionCleanupResult(events, available);
        }
        for (StoredScanJob job : terminalOldestFirst(jobs)) {
            JobDirectoryLayout layout = new JobDirectoryLayout(dataRoot, job.scanId());
            long size = treeSize(layout.root());
            cleaner.deleteTerminalJob(layout, job);
            available = usableSpace.usableBytes(dataRoot);
            events.add(event(job.scanId(), RetentionCleanupResult.Scope.ENTIRE_JOB, "LOW_DISK_OLDEST_FIRST", size));
            if (available >= policy.minimumFreeBytes()) {
                break;
            }
        }
        return new RetentionCleanupResult(events, available);
    }

    public boolean canAcceptNewJob() throws IOException {
        return usableSpace.usableBytes(dataRoot) >= policy.minimumFreeBytes();
    }

    private List<StoredScanJob> terminalOldestFirst(List<StoredScanJob> jobs) {
        Objects.requireNonNull(jobs, "jobs");
        Set<UUID> seen = new HashSet<>();
        return jobs.stream().filter(StoredScanJob::terminal)
                .filter(job -> seen.add(job.scanId()))
                .sorted(Comparator.comparing(StoredScanJob::completedAt).thenComparing(StoredScanJob::scanId))
                .toList();
    }

    private java.time.Duration resultRetention(StoredScanJob job) {
        return isFailure(job.status()) ? policy.failedResults() : policy.successfulResults();
    }

    private boolean isFailure(ScanStatus status) {
        return status == ScanStatus.FAILED || status == ScanStatus.CANCELLED || status == ScanStatus.INTERRUPTED;
    }

    private long temporarySize(JobDirectoryLayout layout) throws IOException {
        long total = 0;
        for (String path : List.of("source", "workspace", "build", "codeql-db", "tmp")) {
            total = Math.addExact(total, treeSize(layout.safeResolve(path)));
        }
        return total;
    }

    private long treeSize(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return 0;
        }
        if (Files.isSymbolicLink(root)) {
            throw new IOException("refusing to measure symbolic-link cleanup root: " + root);
        }
        try (var paths = Files.walk(root)) {
            return paths.filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                    .mapToLong(path -> {
                        try {
                            return Files.size(path);
                        } catch (IOException exception) {
                            throw new SizeReadException(exception);
                        }
                    }).sum();
        } catch (SizeReadException exception) {
            throw (IOException) exception.getCause();
        }
    }

    private RetentionCleanupResult.CleanupEvent event(
            UUID scanId, RetentionCleanupResult.Scope scope, String reason, long reclaimed) {
        return new RetentionCleanupResult.CleanupEvent(scanId, scope, reason, reclaimed);
    }

    @FunctionalInterface
    interface UsableSpaceProvider {
        long usableBytes(Path dataRoot) throws IOException;
    }

    private static final class SizeReadException extends RuntimeException {
        private SizeReadException(IOException cause) {
            super(cause);
        }
    }
}
