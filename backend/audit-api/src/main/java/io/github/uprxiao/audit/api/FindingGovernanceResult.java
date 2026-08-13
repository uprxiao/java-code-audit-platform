package io.github.uprxiao.audit.api;

import io.github.uprxiao.audit.finding.Finding;
import java.util.List;

record FindingGovernanceResult(List<Finding> findings, List<String> warnings) {
    FindingGovernanceResult {
        findings = findings == null ? List.of() : List.copyOf(findings);
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }
}
