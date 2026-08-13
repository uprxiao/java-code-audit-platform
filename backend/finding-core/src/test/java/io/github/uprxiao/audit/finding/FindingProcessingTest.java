package io.github.uprxiao.audit.finding;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FindingProcessingTest {

    private final FindingFingerprintService fingerprints = new FindingFingerprintService();

    @Test
    void fingerprintsAreStableAcrossLineMovementAndRuleAliases() {
        var first = fingerprints.source("SQLI", "src/main/java/App.java", "UserDao.find", "Statement.execute",
                "SQL query at line 20", "statement.execute(query)");
        var moved = fingerprints.source("sql-injection", "src/main/java/App.java", "UserDao.find", "Statement.execute",
                "SQL query at line 99", "statement.execute(query)");

        assertEquals(first, moved);
        assertEquals(1, first.version());
        assertTrue(first.value().matches("sha256:[0-9a-f]{64}"));
    }

    @Test
    void mergesSameSqlSinkAcrossThreeEnginesButPreservesAllEvidence() {
        Finding semgrep = sourceFinding("semgrep", 40, 12, "HTTP parameter", "Statement.execute");
        Finding findsecbugs = sourceFinding("findsecbugs", 40, 12, "HTTP parameter", "Statement.execute");
        Finding codeql = sourceFinding("codeql", 40, 12, "HTTP parameter", "Statement.execute");

        FindingDeduplicationResult result = new ConservativeFindingDeduplicator()
                .deduplicate(List.of(semgrep, findsecbugs, codeql));

        assertEquals(1, result.findings().size());
        assertEquals(2, result.mergedCandidateCount());
        assertEquals(List.of("codeql", "findsecbugs", "semgrep"), result.findings().get(0).evidence().stream()
                .map(FindingEvidence::engine).toList());
        assertEquals(3, result.findings().get(0).dataFlows().size());
    }

    @Test
    void neverMergesDifferentDataFlowSourcesEvenWhenSinkAndRuleMatch() {
        Finding requestParameter = sourceFinding("semgrep", 20, 70, "request.getParameter", "Statement.execute");
        Finding header = sourceFinding("codeql", 25, 70, "request.getHeader", "Statement.execute");

        FindingDeduplicationResult result = new ConservativeFindingDeduplicator()
                .deduplicate(List.of(requestParameter, header));

        assertEquals(2, result.findings().size());
        assertEquals(0, result.mergedCandidateCount());
    }

    @Test
    void mergesSameVulnerabilityAndPurlButKeepsDifferentDependencyPathsSeparate() {
        Finding osv = dependencyFinding("osv", List.of("app", "library:1.0"));
        Finding trivy = dependencyFinding("trivy", List.of("app", "library:1.0"));
        Finding otherPath = dependencyFinding("dependency-check", List.of("worker", "library:1.0"));

        FindingDeduplicationResult result = new ConservativeFindingDeduplicator()
                .deduplicate(List.of(osv, trivy, otherPath));

        assertEquals(2, result.findings().size());
        assertEquals(1, result.mergedCandidateCount());
        assertTrue(result.findings().stream().anyMatch(finding -> finding.evidence().size() == 2));
    }

    @Test
    void suppressionSupportsEngineRuleFamilyPathAndExpiry() {
        Finding finding = sourceFinding("semgrep", 20, 70, "parameter", "Statement.execute");
        SuppressionRule expired = new SuppressionRule("old", "", "", "SQLI", "src/**", "", "", "",
                "temporary exception", Instant.parse("2026-01-01T00:00:00Z"));
        SuppressionRule active = new SuppressionRule("accepted", "semgrep", "sql-rule", "SQL_INJECTION",
                "src/main/**", "", "", "", "legacy query", null);

        SuppressionResult result = new FindingSuppressionService().apply(List.of(finding), List.of(expired, active),
                Instant.parse("2026-08-12T00:00:00Z"));

        assertEquals(0, result.activeFindings().size());
        assertEquals("accepted", result.suppressedFindings().get(0).suppression().ruleId());
        assertEquals(1, result.warnings().size());
        assertTrue(result.warnings().get(0).startsWith("SUPPRESSION_EXPIRED:old"));
    }

    @Test
    void pathExclusionsArePortableCoverageFacts() {
        PathExclusionPolicy exclusions = new PathExclusionPolicy(List.of("**/target/**", "generated/*.java"));

        assertTrue(exclusions.excludes("module/target/classes/App.class"));
        assertTrue(exclusions.excludes("generated/Api.java"));
        assertFalse(exclusions.excludes("src/main/java/App.java"));
        assertEquals(List.of("**/target/**", "generated/*.java"), exclusions.coveragePatterns());
        assertThrows(IllegalArgumentException.class, () -> new PathExclusionPolicy(List.of("../outside/**")));
    }

    @Test
    void severityMappingRecordsReasonAndUsesConservativeFallbacks() {
        SeverityMappingService mappings = new SeverityMappingService();

        SeverityMappingResult exploited = mappings.map(new SeverityMappingRequest("osv", "CVE",
                IssueCategory.DEPENDENCY_VULNERABILITY, "", 9.8, true, false, Confidence.HIGH));
        SeverityMappingResult unknown = mappings.map(new SeverityMappingRequest("pmd", "unknown",
                IssueCategory.MAINTAINABILITY, "vendor-new", null, false, false, Confidence.MEDIUM));

        assertEquals(Severity.P1, exploited.severity());
        assertEquals(SeverityMappingService.MAPPING_ID, exploited.mappingId());
        assertTrue(exploited.reason().contains("knownExploited=true"));
        assertEquals(Severity.P3, unknown.severity());
        assertTrue(unknown.fallback());
    }

    private Finding sourceFinding(String engine, int sourceLine, int sinkLine, String sourceLabel, String sinkLabel) {
        SourceLocation source = new SourceLocation("src/main/java/App.java", sourceLine, 1, sourceLine, 10);
        SourceLocation sink = new SourceLocation("src/main/java/App.java", sinkLine, 1, sinkLine, 20);
        DataFlow flow = new DataFlow(engine, List.of(
                new DataFlowNode(0, DataFlowNode.Kind.SOURCE, source, sourceLabel),
                new DataFlowNode(1, DataFlowNode.Kind.SINK, sink, sinkLabel)));
        FindingFingerprintService.Fingerprint fingerprint = fingerprints.source("SQL_INJECTION", sink.path(),
                "UserDao.find", sinkLabel, "SQL query", "statement.execute(query)");
        FindingEvidence evidence = new FindingEvidence(engine, "1.0", "sql-rule", "HIGH",
                "raw/" + engine + "/report.json", "item-1", Map.of("sinkSymbol", sinkLabel,
                        "semanticAnchor", "UserDao.find", "severityMappingId", SeverityMappingService.MAPPING_ID));
        return new Finding(fingerprint.findingId() + "-" + engine, fingerprint.value(), fingerprint.version(),
                IssueCategory.WEB_SECURITY, Severity.P1, Confidence.HIGH, "SQL_INJECTION",
                "SQL注入", "SQL injection", "", "query", "", "use parameters", "app", sink,
                new CodeSnippet(Math.max(1, sinkLine - 1), sinkLine + 1, List.of(sinkLine),
                        "statement.execute(query)", false),
                new VulnerabilityIdentifiers(List.of("CWE-89"), List.of(), List.of(), List.of()),
                null, List.of(flow), List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    private Finding dependencyFinding(String engine, List<String> dependencyPath) {
        ComponentEvidence component = new ComponentEvidence("pkg:maven/org.example/library@1.0", "org.example",
                "library", "1.0", "compile", false, dependencyPath, List.of("1.1"));
        var fingerprint = fingerprints.dependency("CVE-2026-1234", component.purl(), dependencyPath.get(0));
        FindingEvidence evidence = new FindingEvidence(engine, "1.0", "CVE-2026-1234", "HIGH",
                "raw/" + engine + "/report.json", "CVE-2026-1234", Map.of());
        return new Finding(fingerprint.findingId() + "-" + engine, fingerprint.value(), fingerprint.version(),
                IssueCategory.DEPENDENCY_VULNERABILITY, Severity.P1, Confidence.HIGH,
                "DEPENDENCY_VULNERABILITY", "依赖漏洞", "Dependency vulnerability", "", "CVE-2026-1234",
                "", "upgrade", dependencyPath.get(0), null, null,
                new VulnerabilityIdentifiers(List.of(), List.of("CVE-2026-1234"), List.of(), List.of()),
                component, List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
    }
}
