package io.github.uprxiao.audit.api;

import java.nio.file.Path;
import java.time.Instant;

public record ToolInstallationHealth(
        String id,
        String status,
        String version,
        Path executable,
        String sha256,
        String reasonCode,
        String detail,
        Instant checkedAt) {

    public boolean available() {
        return "AVAILABLE".equals(status);
    }
}
