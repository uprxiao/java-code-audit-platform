package io.github.uprxiao.audit.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.scanner.EngineId;
import java.time.Duration;
import java.util.Map;
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
}
