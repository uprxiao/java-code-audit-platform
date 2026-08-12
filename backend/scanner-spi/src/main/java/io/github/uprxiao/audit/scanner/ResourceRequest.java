package io.github.uprxiao.audit.scanner;

import java.util.Objects;

public record ResourceRequest(ResourceClass resourceClass, int cpuWeight, int memoryMb) {

    public ResourceRequest {
        Objects.requireNonNull(resourceClass, "resourceClass");
        if (cpuWeight < 1 || memoryMb < 1) {
            throw new IllegalArgumentException("resource weights must be positive");
        }
    }
}
