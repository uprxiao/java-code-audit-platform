package io.github.uprxiao.audit.orchestrator;

import io.github.uprxiao.audit.scanner.CancellationToken;

@FunctionalInterface
public interface EngineAction {
    EngineExecutionResult execute(CancellationToken cancellationToken) throws Exception;
}
