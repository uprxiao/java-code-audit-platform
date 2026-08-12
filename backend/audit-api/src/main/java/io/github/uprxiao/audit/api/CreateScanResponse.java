package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record CreateScanResponse(
        UUID scanId,
        ScanStatus status,
        ScanProfile profile,
        Instant createdAt,
        List<String> plannedEngines) {
}
