package io.github.uprxiao.audit.report;

import java.util.Map;

public record ReportSummary(
        int uniqueFindingCount,
        int actionableFindingCount,
        int advisoryFindingCount,
        long rawHitCount,
        int suppressedCount,
        Map<String, Integer> severity,
        Map<String, Integer> categories,
        Map<String, Integer> engines,
        Map<String, Integer> modules,
        Map<String, Integer> sbom,
        long durationMs) {
}
