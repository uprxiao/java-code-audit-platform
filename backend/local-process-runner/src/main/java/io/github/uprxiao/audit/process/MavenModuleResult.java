package io.github.uprxiao.audit.process;

import java.util.Objects;

public record MavenModuleResult(String module, Status status) {

    public enum Status {
        SUCCESS,
        FAILURE,
        SKIPPED
    }

    public MavenModuleResult {
        Objects.requireNonNull(module, "module");
        if (module.isBlank()) {
            throw new IllegalArgumentException("module must not be blank");
        }
        Objects.requireNonNull(status, "status");
    }
}
