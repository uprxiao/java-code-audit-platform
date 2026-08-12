package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.orchestrator.PlannedEngine;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.ResourceRequest;

/** Applies the frozen YAML plan to the actual child-process specification. */
final class ExecutionSpecPolicy {

    ExecutionSpec apply(PlannedEngine planned, ExecutionSpec prepared) {
        if (!planned.engine().id().equals(prepared.engine())) {
            throw new IllegalArgumentException("execution plan and scanner specification engine mismatch");
        }
        return new ExecutionSpec(
                prepared.engine(), prepared.command(), prepared.workingDirectory(), prepared.environment(),
                planned.timeout(),
                new ResourceRequest(planned.resourceClass(), planned.weight(), planned.memoryMb()),
                prepared.expectedArtifacts(), prepared.redactionPolicy());
    }
}
