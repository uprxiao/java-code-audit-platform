package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.ScanPhase;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record ScanView(
        UUID scanId,
        ScanStatus status,
        ScanProfile profile,
        ScanPhase phase,
        Map<String, Integer> progress,
        Map<String, Object> summary,
        Map<String, Object> build,
        Instant createdAt,
        Instant startedAt,
        Instant updatedAt,
        Instant completedAt,
        Map<String, Object> failure,
        Map<String, String> links) {
}
