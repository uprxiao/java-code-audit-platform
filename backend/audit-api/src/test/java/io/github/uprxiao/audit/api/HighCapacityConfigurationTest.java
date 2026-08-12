package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.uprxiao.audit.orchestrator.SchedulerConfiguration;
import io.github.uprxiao.audit.scanner.EngineId;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HighCapacityConfigurationTest {

    @Test
    void confirmedServerExampleSatisfiesSchedulerInvariants() throws Exception {
        Path repository = Path.of(System.getProperty("maven.multiModuleProjectDirectory", "../.."))
                .toAbsolutePath().normalize();
        JsonNode audit = new ObjectMapper(new YAMLFactory())
                .readTree(repository.resolve("config/application-high-capacity.yaml").toFile()).path("audit");
        JsonNode concurrency = audit.path("concurrency");
        JsonNode limits = concurrency.path("tool-limits");
        SchedulerConfiguration configuration = new SchedulerConfiguration(
                concurrency.path("max-queued-scan-jobs").asInt(),
                concurrency.path("max-concurrent-scan-jobs").asInt(),
                concurrency.path("max-concurrent-engines").asInt(),
                concurrency.path("max-engines-per-scan").asInt(),
                concurrency.path("weighted-permits").asInt(),
                Map.of(new EngineId("maven"), limits.path("maven").asInt(),
                        new EngineId("dependency-check"), limits.path("dependency-check").asInt(),
                        new EngineId("codeql"), limits.path("codeql").asInt()),
                Duration.ofSeconds(concurrency.path("retry-after-seconds").asLong()));

        assertEquals(100, configuration.maxQueuedScanJobs());
        assertEquals(8, configuration.maxConcurrentScanJobs());
        assertEquals(24, configuration.maxConcurrentEngines());
        assertEquals(4, configuration.maxEnginesPerScan());
        assertEquals(32, configuration.weightedPermits());
        assertEquals(4, configuration.toolLimits().get(new EngineId("maven")));
        assertEquals(2, configuration.toolLimits().get(new EngineId("dependency-check")));
        assertEquals(1, configuration.toolLimits().get(new EngineId("codeql")));
        assertEquals(33_554_432L, audit.path("process").path("max-log-bytes").asLong());
        assertEquals(21_474_836_480L, audit.path("storage").path("max-workspace-bytes-per-job").asLong());
    }
}
