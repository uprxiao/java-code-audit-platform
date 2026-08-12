package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.scanner.CancellationToken;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/** Rate-limited workspace measurement used by process polling loops. */
final class WorkspaceLimitCancellationToken implements CancellationToken {

    private final JobWorkspaceCapacityGuard guard;
    private final Path jobRoot;
    private final CancellationToken delegate;
    private final long intervalNanos;
    private volatile long nextCheckNanos;
    private volatile WorkspaceCapacityException failure;

    WorkspaceLimitCancellationToken(
            JobWorkspaceCapacityGuard guard, Path jobRoot, CancellationToken delegate, Duration interval) {
        this.guard = Objects.requireNonNull(guard);
        this.jobRoot = Objects.requireNonNull(jobRoot);
        this.delegate = delegate == null ? CancellationToken.NONE : delegate;
        this.intervalNanos = Objects.requireNonNull(interval).toNanos();
        if (intervalNanos < 1) throw new IllegalArgumentException("workspace check interval must be positive");
    }

    @Override
    public boolean isCancellationRequested() {
        if (delegate.isCancellationRequested()) return true;
        if (failure != null) return true;
        long now = System.nanoTime();
        if (now < nextCheckNanos) return false;
        synchronized (this) {
            if (failure != null) return true;
            now = System.nanoTime();
            if (now < nextCheckNanos) return false;
            nextCheckNanos = now + intervalNanos;
            inspect();
            return failure != null;
        }
    }

    synchronized void verifyNow() {
        if (failure == null) inspect();
    }

    WorkspaceCapacityException failure() {
        return failure;
    }

    private void inspect() {
        try {
            guard.requireWithinLimit(jobRoot);
        } catch (WorkspaceCapacityException exception) {
            failure = exception;
        } catch (IOException exception) {
            failure = new WorkspaceCapacityException("JOB_WORKSPACE_MEASUREMENT_FAILED",
                    "job workspace size could not be measured", Map.of("cause", exception.getMessage()));
        }
    }
}
