package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.SourceType;

record CreateScanRequest(SourceType sourceType, ScanProfile profile) {
}
