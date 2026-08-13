package io.github.uprxiao.audit.report;

import java.util.Map;

public record ReportSummary(
        int uniqueFindingCount,
        int actionableFindingCount,
        int conditionalFindingCount,
        int advisoryFindingCount,
        long rawHitCount,
        int suppressedCount,
        Map<String, Integer> severity,
        Map<String, Integer> categories,
        Map<String, Integer> engines,
        Map<String, Integer> modules,
        Map<String, Integer> sbom,
        Map<String, Integer> governance,
        long durationMs) {

    public ReportSummary {
        severity = severity == null ? Map.of() : Map.copyOf(severity);
        categories = categories == null ? Map.of() : Map.copyOf(categories);
        engines = engines == null ? Map.of() : Map.copyOf(engines);
        modules = modules == null ? Map.of() : Map.copyOf(modules);
        sbom = sbom == null ? Map.of() : Map.copyOf(sbom);
        // Additive compatibility for reports produced before rule-governance metadata existed.
        governance = governance == null ? Map.of() : Map.copyOf(governance);
    }
}
