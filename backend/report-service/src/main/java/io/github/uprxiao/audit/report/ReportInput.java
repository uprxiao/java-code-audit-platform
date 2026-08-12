package io.github.uprxiao.audit.report;

import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.ScanCoverage;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record ReportInput(
        UUID scanId,
        ScanProfile profile,
        ScanStatus status,
        Instant createdAt,
        Instant completedAt,
        Map<String, Object> source,
        List<Finding> findings,
        ScanCoverage coverage,
        Map<String, Object> sbomSummary,
        Map<String, Object> build,
        Map<String, Object> toolchain,
        List<String> exclusions,
        List<String> warnings,
        String configFingerprint) {

    public ReportInput {
        Objects.requireNonNull(scanId, "scanId");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(completedAt, "completedAt");
        source = source == null ? Map.of() : Map.copyOf(source);
        findings = findings == null ? List.of() : List.copyOf(findings);
        Objects.requireNonNull(coverage, "coverage");
        sbomSummary = sbomSummary == null ? Map.of() : Map.copyOf(sbomSummary);
        build = build == null ? Map.of() : Map.copyOf(build);
        toolchain = toolchain == null ? Map.of() : Map.copyOf(toolchain);
        exclusions = exclusions == null ? List.of() : List.copyOf(exclusions);
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
        if (configFingerprint == null || !configFingerprint.matches("sha256:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("configFingerprint must be a SHA-256 value");
        }
    }
}
