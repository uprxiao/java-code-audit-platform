package io.github.uprxiao.audit.finding;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FindingValidationTest {

    private static final FindingEvidence EVIDENCE = new FindingEvidence(
            "gitleaks", "8.30.0", "generic-api-key", "HIGH", "raw/gitleaks/report.json", "1", Map.of());

    @Test
    void secretFindingRejectsUnredactedSnippet() {
        assertThrows(IllegalArgumentException.class, () -> new Finding(
                "F-1", "sha256:abc", 1, IssueCategory.SECRET_EXPOSURE, Severity.P0, Confidence.HIGH,
                "SECRET", "密钥泄漏", "Secret", "", "", "", "", "",
                new SourceLocation("src/main/App.java", 1, 1, 1, 10),
                new CodeSnippet(1, 1, List.of(1), "token=cleartext", false),
                VulnerabilityIdentifiers.EMPTY, null, List.of(), List.of(EVIDENCE), null, ReviewState.UNREVIEWED));
    }

    @Test
    void dependencyVulnerabilityRequiresComponentEvidence() {
        assertThrows(IllegalArgumentException.class, () -> new Finding(
                "F-2", "sha256:def", 1, IssueCategory.DEPENDENCY_VULNERABILITY, Severity.P1, Confidence.HIGH,
                "CVE", "依赖漏洞", "Vulnerable dependency", "", "", "", "", "app",
                null, null, new VulnerabilityIdentifiers(List.of(), List.of("CVE-2026-1"), List.of(), List.of()),
                null, List.of(), List.of(EVIDENCE), null, ReviewState.UNREVIEWED));
    }
}
