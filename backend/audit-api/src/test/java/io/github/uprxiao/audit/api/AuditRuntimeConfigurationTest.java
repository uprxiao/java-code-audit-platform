package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.orchestrator.ScanJobQueueFullException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class AuditRuntimeConfigurationTest {

    @Test
    void webScanExecutorHasAnExactBoundedQueueAndRetryContract() throws Exception {
        ThreadPoolExecutor executor = new AuditRuntimeConfiguration().scanExecutor(1, 1, 19);
        CountDownLatch running = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try {
            executor.execute(() -> {
                running.countDown();
                try {
                    release.await();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                }
            });
            assertTrue(running.await(5, TimeUnit.SECONDS));
            executor.execute(() -> {
            });

            ScanJobQueueFullException exception = assertThrows(
                    ScanJobQueueFullException.class, () -> executor.execute(() -> {
                    }));
            assertEquals(1, exception.queueLength());
            assertEquals(1, exception.queueCapacity());
            assertEquals(Duration.ofSeconds(19), exception.retryAfter());
        } finally {
            release.countDown();
            executor.shutdownNow();
            executor.awaitTermination(5, TimeUnit.SECONDS);
        }
    }
}
