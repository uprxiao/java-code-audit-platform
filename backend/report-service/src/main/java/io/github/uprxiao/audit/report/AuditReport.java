package io.github.uprxiao.audit.report;

import io.github.uprxiao.audit.finding.Finding;
import java.util.List;
import java.util.Map;

public record AuditReport(
        String schemaVersion,
        Map<String, Object> scan,
        ReportSummary summary,
        Map<String, Object> coverage,
        List<Finding> findings,
        List<Finding> suppressedFindings,
        Map<String, Object> sbomSummary,
        List<Map<String, Object>> engines,
        Map<String, Object> build,
        Map<String, Object> toolchain,
        List<String> exclusions,
        List<String> warnings,
        List<Map<String, Object>> artifacts) {
}
