package io.github.uprxiao.audit.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.uprxiao.audit.scanner.EngineId;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SchedulerConfigurationTest {

    @Test
    void validatesFrozenDefaultsAndHighCapacityServerExample() {
        SchedulerConfiguration defaults = SchedulerConfiguration.defaults();
        assertEquals(20, defaults.maxQueuedScanJobs());
        assertEquals(2, defaults.maxConcurrentScanJobs());
        assertEquals(4, defaults.maxConcurrentEngines());
        assertEquals(2, defaults.maxEnginesPerScan());
        assertEquals(8, defaults.weightedPermits());

        SchedulerConfiguration highCapacity = new SchedulerConfiguration(
                100, 8, 24, 4, 32,
                Map.of(new EngineId("maven"), 4,
                        new EngineId("dependency-check"), 2,
                        new EngineId("codeql"), 1),
                Duration.ofSeconds(30));
        assertEquals(24, highCapacity.maxConcurrentEngines());
        assertEquals(4, highCapacity.toolLimits().get(new EngineId("maven")));
    }

    @Test
    void rejectsImpossibleRelationships() {
        assertThrows(IllegalArgumentException.class, () -> new SchedulerConfiguration(
                20, 2, 2, 3, 8, Map.of(), Duration.ofSeconds(30)));
        assertThrows(IllegalArgumentException.class, () -> new SchedulerConfiguration(
                20, 2, 4, 2, 8, Map.of(new EngineId("maven"), 5), Duration.ofSeconds(30)));
    }
}
