package io.github.uprxiao.audit.scanner;

import java.io.IOException;

public interface ExecutionBackend {
    ExecutionResult execute(ExecutionSpec specification, CancellationToken cancellationToken)
            throws IOException, InterruptedException;
}
