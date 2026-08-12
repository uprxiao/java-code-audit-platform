package io.github.uprxiao.audit.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.scanner.EngineId;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

class FairDagSchedulerTest {

    @Test
    void rejectsBeyondTheBoundedScanQueueWithRetryMetrics() throws Exception {
        SchedulerConfiguration configuration = configuration(1, 1, 1, 1, 1, Map.of());
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try (FairDagScheduler scheduler = new FairDagScheduler(configuration)) {
            ScanJobHandle running = scheduler.submit(job("semgrep", token -> {
                started.countDown();
                release.await();
                return EngineExecutionResult.succeeded();
            }));
            assertTrue(started.await(5, TimeUnit.SECONDS));
            ScanJobHandle queued = scheduler.submit(job("checkstyle", token -> EngineExecutionResult.succeeded()));

            ScanJobQueueFullException exception = assertThrows(
                    ScanJobQueueFullException.class,
                    () -> scheduler.submit(job("gitleaks", token -> EngineExecutionResult.succeeded())));
            assertEquals(1, exception.queueLength());
            assertEquals(1, exception.queueCapacity());
            assertEquals(Duration.ofSeconds(30), exception.retryAfter());
            assertEquals(1, scheduler.metrics().queuedScanJobs());

            assertTrue(queued.cancel());
            assertEquals(ScanJobExecutionResult.Disposition.CANCELLED,
                    queued.completion().get(5, TimeUnit.SECONDS).disposition());
            release.countDown();
            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED,
                    running.completion().get(5, TimeUnit.SECONDS).disposition());
        }
    }

    @Test
    void dispatchesDagReadinessAndSkipsFailedDependants() throws Exception {
        EngineId build = id("maven");
        EngineId bytecode = id("spotbugs");
        EngineId source = id("semgrep");
        ScheduledScanJob job = new ScheduledScanJob(UUID.randomUUID(), List.of(
                task(build, Set.of(), 1, token -> EngineExecutionResult.failed("BUILD_FAILED", "compile failed")),
                task(bytecode, Set.of(build), 1, token -> EngineExecutionResult.succeeded()),
                task(source, Set.of(), 1, token -> EngineExecutionResult.succeeded())));
        try (FairDagScheduler scheduler = new FairDagScheduler(configuration(2, 1, 1, 1, 1, Map.of()))) {
            ScanJobExecutionResult result = scheduler.submit(job).completion().get(5, TimeUnit.SECONDS);

            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED_WITH_ERRORS, result.disposition());
            assertEquals(EngineStatus.FAILED, result.engines().get(build));
            assertEquals(EngineStatus.SKIPPED, result.engines().get(bytecode));
            assertEquals(EngineStatus.SUCCEEDED, result.engines().get(source));
            assertEquals(0, scheduler.metrics().permits().enginesInUse());
        }
    }

    @Test
    void completesTwentyJobsWithoutExceedingGlobalWeightOrPerScanLimits() throws Exception {
        SchedulerConfiguration configuration = configuration(20, 8, 4, 1, 4, Map.of());
        AtomicInteger engines = new AtomicInteger();
        AtomicInteger maxEngines = new AtomicInteger();
        AtomicInteger weight = new AtomicInteger();
        AtomicInteger maxWeight = new AtomicInteger();
        CountDownLatch firstWave = new CountDownLatch(2);
        CountDownLatch releaseFirstWave = new CountDownLatch(1);
        List<ScanJobHandle> handles = new ArrayList<>();
        try (FairDagScheduler scheduler = new FairDagScheduler(configuration)) {
            for (int index = 0; index < 20; index++) {
                handles.add(scheduler.submit(job("engine-" + index, token -> {
                    int currentEngines = engines.incrementAndGet();
                    maxEngines.accumulateAndGet(currentEngines, Math::max);
                    int currentWeight = weight.addAndGet(2);
                    maxWeight.accumulateAndGet(currentWeight, Math::max);
                    firstWave.countDown();
                    releaseFirstWave.await();
                    weight.addAndGet(-2);
                    engines.decrementAndGet();
                    return EngineExecutionResult.succeeded();
                }, 2)));
            }
            assertTrue(firstWave.await(5, TimeUnit.SECONDS));
            assertTrue(scheduler.metrics().activeScanJobs() >= 2);
            assertTrue(scheduler.metrics().activeScanJobs() <= 8);
            releaseFirstWave.countDown();
            for (ScanJobHandle handle : handles) {
                assertEquals(ScanJobExecutionResult.Disposition.COMPLETED,
                        handle.completion().get(10, TimeUnit.SECONDS).disposition());
            }
            assertTrue(maxEngines.get() <= 2,
                    "two permits per engine in a pool of four permits allows at most two engines");
            assertTrue(maxWeight.get() <= 4);
            assertEquals(0, scheduler.metrics().permits().weightInUse());
            assertTrue(scheduler.metrics().permits().scansInUse().isEmpty());
        }
    }

    @Test
    void aLargeJobDoesNotStarveLaterSmallJobs() throws Exception {
        CountDownLatch largeStarted = new CountDownLatch(1);
        CountDownLatch releaseLarge = new CountDownLatch(1);
        CountDownLatch smallFinished = new CountDownLatch(2);
        List<ScheduledEngineTask> largeTasks = new ArrayList<>();
        for (int index = 0; index < 5; index++) {
            largeTasks.add(task(id("large-" + index), Set.of(), 1, token -> {
                largeStarted.countDown();
                releaseLarge.await();
                return EngineExecutionResult.succeeded();
            }));
        }
        try (FairDagScheduler scheduler = new FairDagScheduler(configuration(5, 3, 3, 1, 3, Map.of()))) {
            ScanJobHandle large = scheduler.submit(new ScheduledScanJob(UUID.randomUUID(), largeTasks));
            assertTrue(largeStarted.await(5, TimeUnit.SECONDS));
            ScanJobHandle smallOne = scheduler.submit(job("small-one", token -> {
                smallFinished.countDown();
                return EngineExecutionResult.succeeded();
            }));
            ScanJobHandle smallTwo = scheduler.submit(job("small-two", token -> {
                smallFinished.countDown();
                return EngineExecutionResult.succeeded();
            }));

            assertTrue(smallFinished.await(5, TimeUnit.SECONDS));
            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED,
                    smallOne.completion().get(5, TimeUnit.SECONDS).disposition());
            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED,
                    smallTwo.completion().get(5, TimeUnit.SECONDS).disposition());
            assertFalse(large.completion().isDone());
            releaseLarge.countDown();
            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED,
                    large.completion().get(5, TimeUnit.SECONDS).disposition());
        }
    }

    @Test
    void toolPermitAndExceptionalCompletionReleaseImmediately() throws Exception {
        EngineId maven = id("maven");
        SchedulerConfiguration configuration = configuration(5, 4, 4, 2, 8, Map.of(maven, 1));
        AtomicInteger mavenInUse = new AtomicInteger();
        AtomicInteger maxMaven = new AtomicInteger();
        CountDownLatch secondStarted = new CountDownLatch(1);
        try (FairDagScheduler scheduler = new FairDagScheduler(configuration)) {
            ScanJobHandle failed = scheduler.submit(new ScheduledScanJob(UUID.randomUUID(), List.of(
                    new ScheduledEngineTask(id("build-one"), Set.of(), 4, maven, token -> {
                        int current = mavenInUse.incrementAndGet();
                        maxMaven.accumulateAndGet(current, Math::max);
                        mavenInUse.decrementAndGet();
                        throw new IllegalStateException("parser failed");
                    }))));
            ScanJobHandle succeeding = scheduler.submit(new ScheduledScanJob(UUID.randomUUID(), List.of(
                    new ScheduledEngineTask(id("build-two"), Set.of(), 4, maven, token -> {
                        int current = mavenInUse.incrementAndGet();
                        maxMaven.accumulateAndGet(current, Math::max);
                        secondStarted.countDown();
                        mavenInUse.decrementAndGet();
                        return EngineExecutionResult.succeeded();
                    }))));

            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED_WITH_ERRORS,
                    failed.completion().get(5, TimeUnit.SECONDS).disposition());
            assertTrue(secondStarted.await(5, TimeUnit.SECONDS));
            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED,
                    succeeding.completion().get(5, TimeUnit.SECONDS).disposition());
            assertEquals(1, maxMaven.get());
            assertEquals(0, scheduler.metrics().permits().toolsInUse().get(maven));
        }
    }

    @Test
    void cancellationReleasesPermitsAndAllowsTheNextJobToRun() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try (FairDagScheduler scheduler = new FairDagScheduler(configuration(2, 1, 1, 1, 1, Map.of()))) {
            ScanJobHandle cancelled = scheduler.submit(job("cancel-me", token -> {
                started.countDown();
                release.await();
                return token.isCancellationRequested()
                        ? EngineExecutionResult.cancelled()
                        : EngineExecutionResult.succeeded();
            }));
            assertTrue(started.await(5, TimeUnit.SECONDS));
            assertTrue(cancelled.cancel());
            release.countDown();
            assertEquals(ScanJobExecutionResult.Disposition.CANCELLED,
                    cancelled.completion().get(5, TimeUnit.SECONDS).disposition());

            ScanJobHandle next = scheduler.submit(job("after-cancel", token -> EngineExecutionResult.succeeded()));
            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED,
                    next.completion().get(5, TimeUnit.SECONDS).disposition());
            assertEquals(0, scheduler.metrics().permits().enginesInUse());
        }
    }

    @Test
    void gracefulShutdownDefersQueuedJobsAndStopsAdmission() throws Exception {
        CountDownLatch activeStarted = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        FairDagScheduler scheduler = new FairDagScheduler(configuration(2, 1, 1, 1, 1, Map.of()));
        ExecutorService shutdownCaller = Executors.newSingleThreadExecutor();
        try {
            ScanJobHandle active = scheduler.submit(job("active", token -> {
                activeStarted.countDown();
                release.await();
                return EngineExecutionResult.succeeded();
            }));
            assertTrue(activeStarted.await(5, TimeUnit.SECONDS));
            ScanJobHandle queued = scheduler.submit(job("queued", token -> EngineExecutionResult.succeeded()));

            var shutdown = shutdownCaller.submit(() -> scheduler.shutdownGracefully(Duration.ofSeconds(5)));
            while (scheduler.metrics().accepting()) {
                Thread.onSpinWait();
            }
            assertThrows(SchedulerShuttingDownException.class,
                    () -> scheduler.submit(job("rejected", token -> EngineExecutionResult.succeeded())));
            assertEquals(ScanJobExecutionResult.Disposition.DEFERRED_FOR_RESTART,
                    queued.completion().get(5, TimeUnit.SECONDS).disposition());
            release.countDown();
            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED,
                    active.completion().get(5, TimeUnit.SECONDS).disposition());
            shutdown.get(10, TimeUnit.SECONDS);
        } finally {
            release.countDown();
            scheduler.close();
            shutdownCaller.shutdownNow();
        }
    }

    @Test
    void listenerObservesReadyRunningAndTerminalStatesInOrder() throws Exception {
        List<EngineStatus> observed = new CopyOnWriteArrayList<>();
        ScanJobListener listener = new ScanJobListener() {
            @Override
            public void onEngineStateChanged(
                    UUID scanId,
                    EngineId engineId,
                    EngineStatus status,
                    io.github.uprxiao.audit.finding.FailureDetails failure) {
                observed.add(status);
            }
        };
        ScheduledScanJob job = new ScheduledScanJob(
                UUID.randomUUID(),
                List.of(task(id("ordered"), Set.of(), 1, token -> EngineExecutionResult.succeeded())),
                listener);
        try (FairDagScheduler scheduler = new FairDagScheduler(configuration(2, 1, 1, 1, 1, Map.of()))) {
            scheduler.submit(job).completion().get(5, TimeUnit.SECONDS);
            assertEquals(List.of(EngineStatus.READY, EngineStatus.RUNNING, EngineStatus.SUCCEEDED), observed);
        }
    }

    @Test
    void listenerAndActionErrorsCannotLeakPermitsOrStopTheDispatcher() throws Exception {
        ScanJobListener brokenListener = new ScanJobListener() {
            @Override
            public void onEngineStateChanged(
                    UUID scanId,
                    EngineId engineId,
                    EngineStatus status,
                    io.github.uprxiao.audit.finding.FailureDetails failure) {
                throw new AssertionError("observer failed");
            }
        };
        try (FairDagScheduler scheduler = new FairDagScheduler(configuration(2, 1, 1, 1, 1, Map.of()))) {
            ScheduledScanJob broken = new ScheduledScanJob(
                    UUID.randomUUID(),
                    List.of(task(id("broken"), Set.of(), 1, token -> {
                        throw new AssertionError("engine failed");
                    })),
                    brokenListener);
            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED_WITH_ERRORS,
                    scheduler.submit(broken).completion().get(5, TimeUnit.SECONDS).disposition());

            ScanJobHandle healthy = scheduler.submit(job(
                    "healthy", token -> EngineExecutionResult.succeeded()));
            assertEquals(ScanJobExecutionResult.Disposition.COMPLETED,
                    healthy.completion().get(5, TimeUnit.SECONDS).disposition());
            assertEquals(0, scheduler.metrics().permits().enginesInUse());
        }
    }

    @Test
    void rejectsReuseOfAScanIdEvenAfterItsFirstExecutionCompleted() throws Exception {
        UUID scanId = UUID.randomUUID();
        ScheduledScanJob original = new ScheduledScanJob(
                scanId, List.of(task(id("original"), Set.of(), 1, token -> EngineExecutionResult.succeeded())));
        ScheduledScanJob duplicate = new ScheduledScanJob(
                scanId, List.of(task(id("duplicate"), Set.of(), 1, token -> EngineExecutionResult.succeeded())));
        try (FairDagScheduler scheduler = new FairDagScheduler(configuration(2, 1, 1, 1, 1, Map.of()))) {
            scheduler.submit(original).completion().get(5, TimeUnit.SECONDS);
            assertThrows(IllegalArgumentException.class, () -> scheduler.submit(duplicate));
        }
    }

    private static ScheduledScanJob job(String engine, EngineAction action) {
        return job(engine, action, 1);
    }

    private static ScheduledScanJob job(String engine, EngineAction action, int weight) {
        return new ScheduledScanJob(UUID.randomUUID(), List.of(task(id(engine), Set.of(), weight, action)));
    }

    private static ScheduledEngineTask task(
            EngineId id, Set<EngineId> dependencies, int weight, EngineAction action) {
        return new ScheduledEngineTask(id, dependencies, weight, action);
    }

    private static EngineId id(String value) {
        return new EngineId(value);
    }

    private static SchedulerConfiguration configuration(
            int queued,
            int jobs,
            int engines,
            int perScan,
            int weighted,
            Map<EngineId, Integer> tools) {
        return new SchedulerConfiguration(
                queued, jobs, engines, perScan, weighted, tools, Duration.ofSeconds(30));
    }
}
