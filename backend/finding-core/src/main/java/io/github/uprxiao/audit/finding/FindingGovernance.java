package io.github.uprxiao.audit.finding;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * A deterministic, auditable assessment layered on top of the immutable detector evidence.
 * It never removes raw evidence or rewrites the engine's original severity.
 */
public record FindingGovernance(
        FindingDisposition disposition,
        FindingApplicability applicability,
        String policyId,
        String rationale,
        List<String> evidence,
        String upstreamSeverity,
        Instant expiresAt) {

    public FindingGovernance {
        Objects.requireNonNull(disposition, "disposition");
        Objects.requireNonNull(applicability, "applicability");
        policyId = normalized(policyId);
        rationale = normalized(rationale);
        evidence = evidence == null ? List.of() : evidence.stream()
                .filter(value -> value != null && !value.isBlank()).map(String::trim).distinct().toList();
        upstreamSeverity = normalized(upstreamSeverity).toUpperCase(java.util.Locale.ROOT);
        if (!policyId.isBlank() && rationale.isBlank()) {
            throw new IllegalArgumentException("governance policy requires a rationale");
        }
    }

    public boolean expired(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }

    public static FindingGovernance defaults(IssueCategory category, Severity severity) {
        if (severity == Severity.P3) {
            return new FindingGovernance(FindingDisposition.ADVISORY, FindingApplicability.UNKNOWN,
                    "", "P3 quality or hygiene result", List.of(), "", null);
        }
        FindingApplicability applicability = category == IssueCategory.DEPENDENCY_VULNERABILITY
                ? FindingApplicability.AFFECTED_VERSION : FindingApplicability.UNKNOWN;
        return new FindingGovernance(FindingDisposition.ACTIONABLE, applicability,
                "", "detector result has not received contextual review", List.of(), "", null);
    }

    private static String normalized(String value) {
        return value == null ? "" : value.trim();
    }
}
