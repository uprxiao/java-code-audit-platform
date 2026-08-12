package io.github.uprxiao.audit.scanner;

import java.util.Objects;

public record Applicability(Status status, String reasonCode, String detail) {

    public enum Status {
        APPLICABLE,
        NOT_APPLICABLE,
        UNAVAILABLE
    }

    public Applicability {
        Objects.requireNonNull(status, "status");
        reasonCode = reasonCode == null ? "" : reasonCode;
        detail = detail == null ? "" : detail;
        if (status != Status.APPLICABLE && reasonCode.isBlank()) {
            throw new IllegalArgumentException("non-applicable result requires a reason code");
        }
    }

    public static Applicability applicable() {
        return new Applicability(Status.APPLICABLE, "", "");
    }
}
