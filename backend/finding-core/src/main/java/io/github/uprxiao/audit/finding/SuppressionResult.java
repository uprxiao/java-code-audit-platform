package io.github.uprxiao.audit.finding;

import java.util.List;

public record SuppressionResult(List<Finding> findings, List<String> warnings) {
    public SuppressionResult {
        findings = List.copyOf(findings);
        warnings = List.copyOf(warnings);
    }

    public List<Finding> activeFindings() {
        return findings.stream().filter(finding -> !finding.suppressed()).toList();
    }

    public List<Finding> suppressedFindings() {
        return findings.stream().filter(Finding::suppressed).toList();
    }
}
