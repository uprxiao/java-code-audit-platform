package io.github.uprxiao.audit.scanner;

import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.Finding;
import java.util.List;
import java.util.Objects;

public record NormalizationResult(List<Finding> findings, EngineCoverage coverage, List<String> warnings) {

    public NormalizationResult {
        findings = findings == null ? List.of() : List.copyOf(findings);
        Objects.requireNonNull(coverage, "coverage");
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }
}
