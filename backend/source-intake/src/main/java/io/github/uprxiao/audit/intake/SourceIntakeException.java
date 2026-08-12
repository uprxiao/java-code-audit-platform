package io.github.uprxiao.audit.intake;

import java.io.IOException;
import java.util.Map;

public final class SourceIntakeException extends IOException {

    private final String code;
    private final Map<String, Object> details;

    public SourceIntakeException(String code, String message) {
        this(code, message, Map.of());
    }

    public SourceIntakeException(String code, String message, Map<String, Object> details) {
        super(message);
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("intake error code must not be blank");
        }
        this.code = code;
        this.details = details == null ? Map.of() : Map.copyOf(details);
    }

    public String code() {
        return code;
    }

    public Map<String, Object> details() {
        return details;
    }
}
