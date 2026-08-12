package io.github.uprxiao.audit.scanner;

import java.time.Instant;
import java.util.Objects;

public record ToolHealth(Status status, String version, String reasonCode, String detail, Instant checkedAt) {

    public enum Status {
        AVAILABLE,
        UNAVAILABLE,
        INCOMPATIBLE
    }

    public ToolHealth {
        Objects.requireNonNull(status, "status");
        version = version == null ? "" : version;
        reasonCode = reasonCode == null ? "" : reasonCode;
        detail = detail == null ? "" : detail;
        Objects.requireNonNull(checkedAt, "checkedAt");
        if (status != Status.AVAILABLE && reasonCode.isBlank()) {
            throw new IllegalArgumentException("unhealthy tool requires a reason code");
        }
    }
}
