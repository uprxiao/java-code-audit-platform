package io.github.uprxiao.audit.api;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

public record ApiErrorResponse(
        Instant timestamp,
        int status,
        ApiErrorCode code,
        String message,
        Map<String, Object> details,
        String requestId) {

    public ApiErrorResponse {
        Objects.requireNonNull(timestamp, "timestamp");
        if (status < 400 || status > 599) {
            throw new IllegalArgumentException("error response status must be 4xx or 5xx");
        }
        Objects.requireNonNull(code, "code");
        if (message == null || message.isBlank()) {
            throw new IllegalArgumentException("message must not be blank");
        }
        details = details == null ? Map.of() : Map.copyOf(details);
        requestId = requestId == null ? "" : requestId;
    }
}
