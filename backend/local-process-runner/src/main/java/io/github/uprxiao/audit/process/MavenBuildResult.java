package io.github.uprxiao.audit.process;

import io.github.uprxiao.audit.scanner.ExecutionResult;
import java.util.List;
import java.util.Objects;

public record MavenBuildResult(Status status, ExecutionResult execution, List<MavenModuleResult> modules) {

    public enum Status {
        SUCCEEDED,
        FAILED,
        TIMED_OUT,
        CANCELLED
    }

    public MavenBuildResult {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(execution, "execution");
        modules = modules == null ? List.of() : List.copyOf(modules);
    }
}
