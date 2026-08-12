package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.FailureDetails;
import io.github.uprxiao.audit.scanner.EngineId;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A single-instance, in-memory dispatcher for already persisted scan jobs.
 *
 * <p>The dispatcher admits a bounded number of waiting jobs, activates at most the configured
 * number of scan jobs, and takes at most one ready engine from each job per round. Resource
 * permits are acquired before work reaches the worker executor, so the executor itself never
 * becomes an unbounded hidden engine queue.</p>
 */
public final class FairDagScheduler implements AutoCloseable {

    private static final AtomicInteger THREAD_SEQUENCE = new AtomicInteger();

    private final SchedulerConfiguration configuration;
    private final EnginePermitManager permits;
    private final Clock clock;
    private final ExecutorService workers;
    private final Thread dispatcher;
    private final ReentrantLock lock = new ReentrantLock(true);
    private final Condition changed = lock.newCondition();
    private final ArrayDeque<JobRuntime> waiting = new ArrayDeque<>();
    private final LinkedHashMap<UUID, JobRuntime> active = new LinkedHashMap<>();
    private final ArrayDeque<UUID> roundRobin = new ArrayDeque<>();
    private final Set<UUID> scheduledScanIds = new HashSet<>();
    private boolean accepting = true;
    private boolean closed;

    public FairDagScheduler(SchedulerConfiguration configuration) {
        this(configuration, Clock.systemUTC());
    }

    FairDagScheduler(SchedulerConfiguration configuration, Clock clock) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.permits = new EnginePermitManager(
                configuration.maxConcurrentEngines(),
                configuration.maxEnginesPerScan(),
                configuration.weightedPermits(),
                configuration.toolLimits());
        this.workers = Executors.newFixedThreadPool(configuration.maxConcurrentEngines(), runnable -> {
            Thread thread = new Thread(runnable, "audit-engine-worker-" + THREAD_SEQUENCE.incrementAndGet());
            thread.setDaemon(false);
            return thread;
        });
        this.dispatcher = new Thread(this::dispatchLoop, "audit-engine-dispatcher");
        this.dispatcher.setDaemon(false);
        this.dispatcher.start();
    }

    public ScanJobHandle submit(ScheduledScanJob job) {
        Objects.requireNonNull(job, "job");
        for (ScheduledEngineTask engine : job.engines()) {
            if (engine.weight() > configuration.weightedPermits()) {
                throw new IllegalArgumentException(
                        engine.id() + " weight exceeds the configured weighted permit pool");
            }
        }
        JobRuntime runtime = new JobRuntime(job);
        List<Runnable> notifications = new ArrayList<>();
        lock.lock();
        try {
            if (!accepting) {
                throw new SchedulerShuttingDownException();
            }
            if (scheduledScanIds.contains(job.scanId())) {
                throw new IllegalArgumentException("scan job is already scheduled: " + job.scanId());
            }
            if (active.size() >= configuration.maxConcurrentScanJobs()
                    && waiting.size() >= configuration.maxQueuedScanJobs()) {
                throw new ScanJobQueueFullException(
                        waiting.size(), configuration.maxQueuedScanJobs(), configuration.retryAfter());
            }
            if (active.size() < configuration.maxConcurrentScanJobs()) {
                activateLocked(runtime, notifications);
            } else {
                waiting.addLast(runtime);
            }
            scheduledScanIds.add(job.scanId());
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        notifyAll(notifications);
        lock.lock();
        try {
            runtime.dispatchable = true;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        return new ScanJobHandle(
                job.scanId(), runtime.completion,
                () -> cancel(runtime),
                () -> snapshot(runtime));
    }

    public SchedulerMetrics metrics() {
        lock.lock();
        try {
            return new SchedulerMetrics(
                    waiting.size(), configuration.maxQueuedScanJobs(),
                    active.size(), configuration.maxConcurrentScanJobs(),
                    accepting, permits.snapshot());
        } finally {
            lock.unlock();
        }
    }

    public void shutdownGracefully(Duration gracePeriod) {
        Objects.requireNonNull(gracePeriod, "gracePeriod");
        if (gracePeriod.isNegative()) {
            throw new IllegalArgumentException("gracePeriod must not be negative");
        }
        List<Runnable> notifications = new ArrayList<>();
        long deadline = System.nanoTime() + gracePeriod.toNanos();
        lock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            accepting = false;
            while (!waiting.isEmpty()) {
                JobRuntime queued = waiting.removeFirst();
                completeLocked(queued, ScanJobExecutionResult.Disposition.DEFERRED_FOR_RESTART, notifications);
            }
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        notifyAll(notifications);

        awaitActiveJobs(deadline);

        notifications = new ArrayList<>();
        lock.lock();
        try {
            for (JobRuntime runtime : List.copyOf(active.values())) {
                cancelLocked(runtime, notifications);
            }
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        notifyAll(notifications);

        long cancellationDeadline = System.nanoTime()
                + Math.max(TimeUnit.SECONDS.toNanos(1), Math.min(TimeUnit.SECONDS.toNanos(5), gracePeriod.toNanos()));
        awaitActiveJobs(cancellationDeadline);

        lock.lock();
        try {
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        workers.shutdown();
        try {
            if (!workers.awaitTermination(1, TimeUnit.SECONDS)) {
                workers.shutdownNow();
                workers.awaitTermination(5, TimeUnit.SECONDS);
            }
            dispatcher.join(TimeUnit.SECONDS.toMillis(5));
        } catch (InterruptedException exception) {
            workers.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        shutdownGracefully(Duration.ofSeconds(5));
    }

    private void dispatchLoop() {
        while (true) {
            Launch launch = null;
            List<Runnable> notifications = new ArrayList<>();
            lock.lock();
            try {
                while (launch == null) {
                    activateWaitingLocked(notifications);
                    launch = dispatchOneLocked(notifications);
                    if (launch != null || !notifications.isEmpty()) {
                        break;
                    }
                    if (closed && active.isEmpty() && waiting.isEmpty()) {
                        return;
                    }
                    changed.await();
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return;
            } finally {
                lock.unlock();
            }
            notifyAll(notifications);
            if (launch != null) {
                submitLaunch(launch);
            }
        }
    }

    private void submitLaunch(Launch launch) {
        try {
            workers.execute(() -> execute(launch));
        } catch (RejectedExecutionException exception) {
            launch.lease.close();
            completeEngine(launch, EngineExecutionResult.failed(
                    "ENGINE_EXECUTOR_STOPPED", "engine worker executor rejected the task"));
        }
    }

    private void execute(Launch launch) {
        EngineExecutionResult result;
        try (EnginePermitManager.PermitLease ignored = launch.lease) {
            if (launch.runtime.cancelRequested) {
                result = EngineExecutionResult.cancelled();
            } else {
                result = launch.task.definition.action().execute(() -> launch.runtime.cancelRequested);
                if (result == null) {
                    result = EngineExecutionResult.failed(
                            "ENGINE_RESULT_MISSING", "engine action returned no result");
                }
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            result = launch.runtime.cancelRequested
                    ? EngineExecutionResult.cancelled()
                    : EngineExecutionResult.failed("ENGINE_INTERRUPTED", "engine worker was interrupted");
        } catch (Throwable exception) {
            result = launch.runtime.cancelRequested
                    ? EngineExecutionResult.cancelled()
                    : EngineExecutionResult.failed(
                            "ENGINE_EXECUTION_EXCEPTION",
                            exception.getMessage() == null ? exception.getClass().getSimpleName() : exception.getMessage());
        }
        completeEngine(launch, result);
    }

    private void completeEngine(Launch launch, EngineExecutionResult result) {
        List<Runnable> notifications = new ArrayList<>();
        lock.lock();
        try {
            if (launch.task.status != EngineStatus.RUNNING) {
                return;
            }
            launch.task.status = result.status();
            launch.task.failure = result.failure();
            notifications.add(engineNotification(launch.runtime, launch.task));
            promoteReadyAndSkippedLocked(launch.runtime, notifications);
            finishIfTerminalLocked(launch.runtime, notifications);
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        notifyAll(notifications);
    }

    private Launch dispatchOneLocked(List<Runnable> notifications) throws InterruptedException {
        int jobsThisRound = roundRobin.size();
        for (int index = 0; index < jobsThisRound; index++) {
            UUID scanId = roundRobin.removeFirst();
            JobRuntime runtime = active.get(scanId);
            if (runtime == null) {
                continue;
            }
            if (runtime.cancelRequested) {
                cancelWaitingEnginesLocked(runtime, notifications);
                finishIfTerminalLocked(runtime, notifications);
                if (active.containsKey(scanId)) {
                    roundRobin.addLast(scanId);
                }
                continue;
            }
            if (!runtime.dispatchable) {
                roundRobin.addLast(scanId);
                continue;
            }
            for (TaskRuntime task : runtime.tasks.values()) {
                if (task.status != EngineStatus.READY) {
                    continue;
                }
                Optional<EnginePermitManager.PermitLease> lease = permits.tryAcquire(
                        scanId, task.definition.toolPermit(), task.definition.weight(), Duration.ZERO);
                if (lease.isPresent()) {
                    task.status = EngineStatus.RUNNING;
                    notifications.add(engineNotification(runtime, task));
                    roundRobin.addLast(scanId);
                    return new Launch(runtime, task, lease.get());
                }
            }
            roundRobin.addLast(scanId);
        }
        return null;
    }

    private void activateWaitingLocked(List<Runnable> notifications) {
        while (!waiting.isEmpty() && active.size() < configuration.maxConcurrentScanJobs()) {
            activateLocked(waiting.removeFirst(), notifications);
        }
    }

    private void activateLocked(JobRuntime runtime, List<Runnable> notifications) {
        runtime.started = true;
        active.put(runtime.job.scanId(), runtime);
        roundRobin.addLast(runtime.job.scanId());
        notifications.add(() -> runtime.job.listener().onJobStarted(runtime.job.scanId()));
        promoteReadyAndSkippedLocked(runtime, notifications);
    }

    private void promoteReadyAndSkippedLocked(JobRuntime runtime, List<Runnable> notifications) {
        boolean changedState;
        do {
            changedState = false;
            for (TaskRuntime task : runtime.tasks.values()) {
                if (task.status != EngineStatus.PENDING) {
                    continue;
                }
                List<TaskRuntime> dependencies = task.definition.dependsOn().stream()
                        .map(runtime.tasks::get)
                        .toList();
                Optional<TaskRuntime> failedDependency = dependencies.stream()
                        .filter(dependency -> dependency.status.isTerminal()
                                && dependency.status != EngineStatus.SUCCEEDED
                                && dependency.status != EngineStatus.PARTIAL)
                        .findFirst();
                if (failedDependency.isPresent()) {
                    task.status = EngineStatus.SKIPPED;
                    task.failure = new FailureDetails(
                            "DEPENDENCY_FAILED",
                            "dependency " + failedDependency.get().definition.id() + " ended as "
                                    + failedDependency.get().status,
                            Map.of("dependency", failedDependency.get().definition.id().value(),
                                    "status", failedDependency.get().status.name()));
                    notifications.add(engineNotification(runtime, task));
                    changedState = true;
                } else if (dependencies.stream().allMatch(dependency -> dependency.status.isTerminal())) {
                    task.status = EngineStatus.READY;
                    notifications.add(engineNotification(runtime, task));
                    changedState = true;
                }
            }
        } while (changedState);
    }

    private boolean cancel(JobRuntime runtime) {
        List<Runnable> notifications = new ArrayList<>();
        boolean changedState;
        lock.lock();
        try {
            if (runtime.finished) {
                return false;
            }
            changedState = cancelLocked(runtime, notifications);
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        notifyAll(notifications);
        return changedState;
    }

    private boolean cancelLocked(JobRuntime runtime, List<Runnable> notifications) {
        if (runtime.cancelRequested) {
            return false;
        }
        runtime.cancelRequested = true;
        if (!runtime.started) {
            waiting.remove(runtime);
        }
        cancelWaitingEnginesLocked(runtime, notifications);
        finishIfTerminalLocked(runtime, notifications);
        return true;
    }

    private void cancelWaitingEnginesLocked(JobRuntime runtime, List<Runnable> notifications) {
        for (TaskRuntime task : runtime.tasks.values()) {
            if (task.status == EngineStatus.PENDING || task.status == EngineStatus.READY) {
                task.status = EngineStatus.CANCELLED;
                notifications.add(engineNotification(runtime, task));
            }
        }
    }

    private void finishIfTerminalLocked(JobRuntime runtime, List<Runnable> notifications) {
        if (runtime.finished
                || runtime.tasks.values().stream().anyMatch(task -> !task.status.isTerminal())) {
            return;
        }
        ScanJobExecutionResult.Disposition disposition;
        if (runtime.cancelRequested) {
            disposition = ScanJobExecutionResult.Disposition.CANCELLED;
        } else if (runtime.tasks.values().stream().anyMatch(task -> task.status != EngineStatus.SUCCEEDED)) {
            disposition = ScanJobExecutionResult.Disposition.COMPLETED_WITH_ERRORS;
        } else {
            disposition = ScanJobExecutionResult.Disposition.COMPLETED;
        }
        completeLocked(runtime, disposition, notifications);
    }

    private void completeLocked(
            JobRuntime runtime,
            ScanJobExecutionResult.Disposition disposition,
            List<Runnable> notifications) {
        if (runtime.finished) {
            return;
        }
        runtime.finished = true;
        active.remove(runtime.job.scanId());
        roundRobin.removeIf(runtime.job.scanId()::equals);
        permits.forgetScan(runtime.job.scanId());
        ScanJobExecutionResult result = new ScanJobExecutionResult(
                runtime.job.scanId(), disposition, snapshotUnlocked(runtime), clock.instant());
        notifications.add(() -> {
            runtime.completion.complete(result);
            runtime.job.listener().onJobFinished(result);
        });
        changed.signalAll();
    }

    private Map<EngineId, EngineStatus> snapshot(JobRuntime runtime) {
        lock.lock();
        try {
            return snapshotUnlocked(runtime);
        } finally {
            lock.unlock();
        }
    }

    private Map<EngineId, EngineStatus> snapshotUnlocked(JobRuntime runtime) {
        Map<EngineId, EngineStatus> result = new LinkedHashMap<>();
        runtime.tasks.forEach((id, task) -> result.put(id, task.status));
        return Map.copyOf(result);
    }

    private Runnable engineNotification(JobRuntime runtime, TaskRuntime task) {
        EngineId engineId = task.definition.id();
        EngineStatus status = task.status;
        FailureDetails failure = task.failure;
        return () -> runtime.job.listener().onEngineStateChanged(
                runtime.job.scanId(), engineId, status, failure);
    }

    private void awaitActiveJobs(long deadline) {
        lock.lock();
        try {
            while (!active.isEmpty()) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    return;
                }
                try {
                    changed.awaitNanos(remaining);
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        } finally {
            lock.unlock();
        }
    }

    private void notifyAll(List<Runnable> notifications) {
        for (Runnable notification : notifications) {
            try {
                notification.run();
            } catch (Throwable ignored) {
                // State and permit correctness must not depend on an observational callback.
            }
        }
    }

    private static final class JobRuntime {
        private final ScheduledScanJob job;
        private final Map<EngineId, TaskRuntime> tasks = new LinkedHashMap<>();
        private final CompletableFuture<ScanJobExecutionResult> completion = new CompletableFuture<>();
        private volatile boolean cancelRequested;
        private boolean started;
        private boolean dispatchable;
        private boolean finished;

        private JobRuntime(ScheduledScanJob job) {
            this.job = job;
            for (ScheduledEngineTask engine : job.engines()) {
                tasks.put(engine.id(), new TaskRuntime(engine));
            }
        }
    }

    private static final class TaskRuntime {
        private final ScheduledEngineTask definition;
        private EngineStatus status = EngineStatus.PENDING;
        private FailureDetails failure;

        private TaskRuntime(ScheduledEngineTask definition) {
            this.definition = definition;
        }
    }

    private record Launch(
            JobRuntime runtime,
            TaskRuntime task,
            EnginePermitManager.PermitLease lease) {
    }
}
