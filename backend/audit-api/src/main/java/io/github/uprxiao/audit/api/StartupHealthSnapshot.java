package io.github.uprxiao.audit.api;

import java.time.Instant;
import java.util.List;

public record StartupHealthSnapshot(
        String status,
        String operatingSystem,
        String architecture,
        String runtimeLibc,
        String javaVersion,
        String mavenVersion,
        String mavenJavaVersion,
        List<ToolInstallationHealth> tools,
        long usableDiskBytes,
        long minimumDiskBytes,
        Instant checkedAt) {
}
