package io.github.uprxiao.audit.finding;

public record SeverityMappingResult(
        Severity severity,
        String mappingId,
        String reason,
        boolean fallback) {
}
