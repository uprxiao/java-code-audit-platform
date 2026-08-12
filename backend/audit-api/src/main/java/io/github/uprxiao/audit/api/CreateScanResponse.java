package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.ScanStatus;
import java.util.List;
import java.util.UUID;

record CreateScanResponse(UUID scanId, ScanStatus status, List<String> plannedEngines) {
}
