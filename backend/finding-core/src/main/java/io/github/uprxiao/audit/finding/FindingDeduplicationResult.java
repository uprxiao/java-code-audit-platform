package io.github.uprxiao.audit.finding;

import java.util.List;

public record FindingDeduplicationResult(
        List<Finding> findings,
        int candidateCount,
        int mergedCandidateCount) {

    public FindingDeduplicationResult {
        findings = List.copyOf(findings);
        if (candidateCount < findings.size() || mergedCandidateCount != candidateCount - findings.size()) {
            throw new IllegalArgumentException("deduplication counts are inconsistent");
        }
    }
}
