package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.uprxiao.audit.orchestrator.PlannedEngine;
import io.github.uprxiao.audit.orchestrator.ScanEngine;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ExecutionSpecPolicyTest {

    @Test
    void yamlPlanOverridesAdapterTimeoutAndResourceRequest() {
        PlannedEngine planned = new PlannedEngine(
                ScanEngine.SEMGREP, false, ResourceClass.HEAVY, 7, 6144,
                Duration.ofSeconds(321), List.of());
        ExecutionSpec prepared = new ExecutionSpec(
                ScanEngine.SEMGREP.id(), List.of("/bin/echo", "test"), Path.of("."), Map.of(),
                Duration.ofSeconds(10), new ResourceRequest(ResourceClass.LIGHT, 1, 128),
                Set.of(), RedactionPolicy.NONE);

        ExecutionSpec effective = new ExecutionSpecPolicy().apply(planned, prepared);

        assertEquals(Duration.ofSeconds(321), effective.timeout());
        assertEquals(ResourceClass.HEAVY, effective.resources().resourceClass());
        assertEquals(7, effective.resources().cpuWeight());
        assertEquals(6144, effective.resources().memoryMb());
        assertEquals(prepared.command(), effective.command());
        assertEquals(prepared.environment(), effective.environment());
    }
}
