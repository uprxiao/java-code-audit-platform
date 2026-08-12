package io.github.uprxiao.audit.api;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;

public record ToolInstallationHealth(
        String id,
        String status,
        String version,
        Path executable,
        String sha256,
        String reasonCode,
        String detail,
        Instant checkedAt,
        Map<String, Object> database) {

    public ToolInstallationHealth(
            String id, String status, String version, Path executable, String sha256,
            String reasonCode, String detail, Instant checkedAt) {
        this(id, status, version, executable, sha256, reasonCode, detail, checkedAt, Map.of());
    }

    public ToolInstallationHealth {
        database = database == null ? Map.of() : Map.copyOf(database);
    }

    public boolean available() {
        return "AVAILABLE".equals(status) || "DEGRADED".equals(status);
    }
}
