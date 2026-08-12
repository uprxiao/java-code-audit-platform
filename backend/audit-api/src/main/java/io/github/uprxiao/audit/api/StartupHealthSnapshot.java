package io.github.uprxiao.audit.api;

import java.time.Instant;

public record StartupHealthSnapshot(
        String status,
        String operatingSystem,
        String architecture,
        String javaVersion,
        String mavenVersion,
        String mavenJavaVersion,
        long usableDiskBytes,
        long minimumDiskBytes,
        Instant checkedAt) {
}
