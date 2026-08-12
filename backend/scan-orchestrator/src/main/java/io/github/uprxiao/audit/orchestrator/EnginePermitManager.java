package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.scanner.EngineId;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class EnginePermitManager {

    private final int globalLimit;
    private final int perScanLimit;
    private final int weightedLimit;
    private final Semaphore global;
    private final Semaphore weighted;
    private final Map<EngineId, Semaphore> tools;
    private final Map<UUID, Semaphore> scans = new ConcurrentHashMap<>();

    public EnginePermitManager(
            int maxConcurrentEngines,
            int maxEnginesPerScan,
            int weightedPermits,
            Map<EngineId, Integer> toolLimits) {
        if (maxConcurrentEngines < 1 || maxEnginesPerScan < 1 || weightedPermits < 1) {
            throw new IllegalArgumentException("permit limits must be positive");
        }
        if (maxEnginesPerScan > maxConcurrentEngines) {
            throw new IllegalArgumentException("per-scan engine limit cannot exceed global limit");
        }
        this.globalLimit = maxConcurrentEngines;
        this.perScanLimit = maxEnginesPerScan;
        this.weightedLimit = weightedPermits;
        this.global = new Semaphore(maxConcurrentEngines, true);
        this.weighted = new Semaphore(weightedPermits, true);
        toolLimits = toolLimits == null ? Map.of() : Map.copyOf(toolLimits);
        Map<EngineId, Semaphore> configuredTools = new ConcurrentHashMap<>();
        toolLimits.forEach((id, limit) -> {
            if (limit == null || limit < 1 || limit > maxConcurrentEngines) {
                throw new IllegalArgumentException("invalid tool limit for " + id);
            }
            configuredTools.put(id, new Semaphore(limit, true));
        });
        this.tools = Map.copyOf(configuredTools);
    }

    public Optional<PermitLease> tryAcquire(
            UUID scanId, EngineId engineId, int weight, Duration maximumWait) throws InterruptedException {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(engineId, "engineId");
        Objects.requireNonNull(maximumWait, "maximumWait");
        if (weight < 1 || weight > weightedLimit) {
            throw new IllegalArgumentException("engine weight must fit the configured weighted permit pool");
        }
        if (maximumWait.isNegative()) {
            throw new IllegalArgumentException("maximumWait must not be negative");
        }
        Semaphore scan = scans.computeIfAbsent(scanId, ignored -> new Semaphore(perScanLimit, true));
        Semaphore tool = tools.get(engineId);
        long deadline = System.nanoTime() + maximumWait.toNanos();
        do {
            boolean globalAcquired = global.tryAcquire();
            boolean scanAcquired = false;
            boolean weightAcquired = false;
            boolean toolAcquired = false;
            if (globalAcquired) {
                scanAcquired = scan.tryAcquire();
            }
            if (scanAcquired) {
                weightAcquired = weighted.tryAcquire(weight);
            }
            if (weightAcquired) {
                toolAcquired = tool == null || tool.tryAcquire();
            }
            if (globalAcquired && scanAcquired && weightAcquired && toolAcquired) {
                return Optional.of(new PermitLease(global, scan, weighted, tool, weight));
            }
            if (toolAcquired && tool != null) {
                tool.release();
            }
            if (weightAcquired) {
                weighted.release(weight);
            }
            if (scanAcquired) {
                scan.release();
            }
            if (globalAcquired) {
                global.release();
            }
            long remaining = deadline - System.nanoTime();
            if (remaining > 0) {
                TimeUnit.NANOSECONDS.sleep(Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(10)));
            }
        } while (System.nanoTime() < deadline);
        return Optional.empty();
    }

    public PermitSnapshot snapshot() {
        return new PermitSnapshot(
                globalLimit - global.availablePermits(), globalLimit,
                weightedLimit - weighted.availablePermits(), weightedLimit);
    }

    public void forgetScan(UUID scanId) {
        Semaphore semaphore = scans.get(scanId);
        if (semaphore != null && semaphore.availablePermits() == perScanLimit) {
            scans.remove(scanId, semaphore);
        }
    }

    public record PermitSnapshot(int enginesInUse, int engineLimit, int weightInUse, int weightLimit) {
    }

    public static final class PermitLease implements AutoCloseable {
        private final Semaphore global;
        private final Semaphore scan;
        private final Semaphore weighted;
        private final Semaphore tool;
        private final int weight;
        private final AtomicBoolean closed = new AtomicBoolean();

        private PermitLease(Semaphore global, Semaphore scan, Semaphore weighted, Semaphore tool, int weight) {
            this.global = global;
            this.scan = scan;
            this.weighted = weighted;
            this.tool = tool;
            this.weight = weight;
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                if (tool != null) {
                    tool.release();
                }
                weighted.release(weight);
                scan.release();
                global.release();
            }
        }
    }
}
