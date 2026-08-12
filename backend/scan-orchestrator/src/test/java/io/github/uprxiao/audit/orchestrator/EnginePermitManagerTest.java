package io.github.uprxiao.audit.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.scanner.EngineId;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class EnginePermitManagerTest {

    @Test
    void releasesEveryPermitAfterSuccessAndException() throws Exception {
        EngineId codeql = new EngineId("codeql");
        EnginePermitManager manager = new EnginePermitManager(2, 1, 8, Map.of(codeql, 1));
        UUID firstScan = UUID.randomUUID();

        try (EnginePermitManager.PermitLease ignored = manager
                .tryAcquire(firstScan, codeql, 8, Duration.ZERO).orElseThrow()) {
            assertEquals(1, manager.snapshot().enginesInUse());
            assertEquals(8, manager.snapshot().weightInUse());
            assertTrue(manager.tryAcquire(UUID.randomUUID(), codeql, 8, Duration.ofMillis(20)).isEmpty());
        }

        try {
            try (EnginePermitManager.PermitLease ignored = manager
                    .tryAcquire(firstScan, codeql, 8, Duration.ZERO).orElseThrow()) {
                throw new IllegalStateException("parser failed");
            }
        } catch (IllegalStateException expected) {
            assertEquals("parser failed", expected.getMessage());
        }

        assertEquals(0, manager.snapshot().enginesInUse());
        assertEquals(0, manager.snapshot().weightInUse());
        manager.forgetScan(firstScan);
    }

    @Test
    void closeIsIdempotent() throws Exception {
        EnginePermitManager manager = new EnginePermitManager(1, 1, 2, Map.of());
        EnginePermitManager.PermitLease lease = manager
                .tryAcquire(UUID.randomUUID(), new EngineId("semgrep"), 2, Duration.ZERO).orElseThrow();
        lease.close();
        lease.close();
        assertEquals(0, manager.snapshot().enginesInUse());
        assertEquals(0, manager.snapshot().weightInUse());
    }

    @Test
    void compositeLeaseAtomicallyHoldsAndReleasesMavenAndCodeql() throws Exception {
        EngineId maven = new EngineId("maven");
        EngineId codeql = new EngineId("codeql");
        EnginePermitManager manager = new EnginePermitManager(
                3, 2, 12, Map.of(maven, 1, codeql, 1));

        try (EnginePermitManager.PermitLease ignored = manager.tryAcquire(
                UUID.randomUUID(), Set.of(maven, codeql), 8, Duration.ZERO).orElseThrow()) {
            assertEquals(1, manager.snapshot().toolsInUse().get(maven));
            assertEquals(1, manager.snapshot().toolsInUse().get(codeql));
            assertTrue(manager.tryAcquire(
                    UUID.randomUUID(), maven, 4, Duration.ofMillis(20)).isEmpty());
            assertTrue(manager.tryAcquire(
                    UUID.randomUUID(), codeql, 4, Duration.ofMillis(20)).isEmpty());
        }

        assertEquals(0, manager.snapshot().toolsInUse().get(maven));
        assertEquals(0, manager.snapshot().toolsInUse().get(codeql));
    }
}
