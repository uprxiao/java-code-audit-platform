package io.github.uprxiao.audit.finding;

import java.util.Map;
import java.util.Objects;

public record FailureDetails(String code, String message, Map<String, Object> details) {

    public FailureDetails {
        code = requireText(code, "code");
        message = requireText(message, "message");
        details = details == null ? Map.of() : Map.copyOf(details);
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
