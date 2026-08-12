package io.github.uprxiao.audit.api;

import java.io.IOException;
import java.util.Map;

final class WorkspaceCapacityException extends IOException {

    private final String code;
    private final Map<String, Object> details;

    WorkspaceCapacityException(String code, String message, Map<String, Object> details) {
        super(message);
        this.code = code;
        this.details = details == null ? Map.of() : Map.copyOf(details);
    }

    String code() {
        return code;
    }

    Map<String, Object> details() {
        return details;
    }
}
