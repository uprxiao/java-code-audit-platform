package io.github.uprxiao.audit.finding;

import java.util.Locale;

/** Deterministic V1 severity mapping; the mapping id is persisted by adapters in evidence properties. */
public final class SeverityMappingService {

    public static final String MAPPING_ID = "java-audit-severity-v1";

    public SeverityMappingResult map(SeverityMappingRequest request) {
        if (request.category() == IssueCategory.SECRET_EXPOSURE) {
            Severity severity = request.privilegedSecret() && request.confidence() == Confidence.HIGH
                    ? Severity.P0 : Severity.P1;
            return result(severity, "secret type and confidence", false);
        }
        if (request.category() == IssueCategory.DEPENDENCY_VULNERABILITY && request.cvss() != null) {
            double score = request.cvss();
            Severity severity;
            if (score >= 9.0 && request.knownExploited()) {
                severity = Severity.P0;
            } else if (score >= 7.0) {
                severity = Severity.P1;
            } else if (score >= 4.0) {
                severity = Severity.P2;
            } else {
                severity = Severity.P3;
            }
            return result(severity, "CVSS=" + score + ", knownExploited=" + request.knownExploited(), false);
        }
        String original = request.engineSeverity().toUpperCase(Locale.ROOT);
        return switch (original) {
            case "CRITICAL", "BLOCKER" -> result(Severity.P0, "engine severity " + original, false);
            case "HIGH", "ERROR", "1" -> result(Severity.P1, "engine severity " + original, false);
            case "MEDIUM", "MODERATE", "WARNING", "WARN", "2" ->
                    result(Severity.P2, "engine severity " + original, false);
            case "LOW", "INFO", "INFORMATIONAL", "NOTE", "3", "4", "5" ->
                    result(Severity.P3, "engine severity " + original, false);
            default -> result(defaultFor(request.category()),
                    "unknown engine severity; conservative category fallback", true);
        };
    }

    private Severity defaultFor(IssueCategory category) {
        return switch (category) {
            case WEB_SECURITY, DEPENDENCY_VULNERABILITY -> Severity.P1;
            case CORRECTNESS, CONCURRENCY, RESOURCE_PERFORMANCE, CONFIG_IAC_SECURITY,
                    LICENSE_SUPPLY_CHAIN -> Severity.P2;
            case MAINTAINABILITY, CODE_STYLE, DUPLICATION, BUILD_GOVERNANCE -> Severity.P3;
            case SECRET_EXPOSURE -> Severity.P1;
        };
    }

    private SeverityMappingResult result(Severity severity, String reason, boolean fallback) {
        return new SeverityMappingResult(severity, MAPPING_ID, reason, fallback);
    }
}
