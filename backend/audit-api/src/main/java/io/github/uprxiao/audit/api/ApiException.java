package io.github.uprxiao.audit.api;

import java.util.Map;
import org.springframework.http.HttpStatus;

final class ApiException extends RuntimeException {

    private final HttpStatus status;
    private final ApiErrorCode code;
    private final Map<String, Object> details;

    ApiException(HttpStatus status, ApiErrorCode code, String message) {
        this(status, code, message, Map.of());
    }

    ApiException(HttpStatus status, ApiErrorCode code, String message, Map<String, Object> details) {
        super(message);
        this.status = status;
        this.code = code;
        this.details = details == null ? Map.of() : Map.copyOf(details);
    }

    HttpStatus status() {
        return status;
    }

    ApiErrorCode code() {
        return code;
    }

    Map<String, Object> details() {
        return details;
    }
}
