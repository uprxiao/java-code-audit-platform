package io.github.uprxiao.audit.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.finding.CodeSnippet;
import io.github.uprxiao.audit.finding.Confidence;
import io.github.uprxiao.audit.finding.DataFlow;
import io.github.uprxiao.audit.finding.DataFlowNode;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingEvidence;
import io.github.uprxiao.audit.finding.FindingFingerprintService;
import io.github.uprxiao.audit.finding.FindingSuppression;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ReviewState;
import io.github.uprxiao.audit.finding.ScanCoverage;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import io.github.uprxiao.audit.finding.Severity;
import io.github.uprxiao.audit.finding.SourceLocation;
import io.github.uprxiao.audit.finding.VulnerabilityIdentifiers;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReportSecurityAndDeduplicationTest {

    private static final String EXACT_SECRET = "TOP-SECRET-unusual-value";
    private static final String CANARY = "AUDIT_CANARY_SECRET_ABC987";
    private static final Instant START = Instant.parse("2026-08-12T00:00:00Z");

    @TempDir
    Path temporaryDirectory;

    private final ObjectMapper json = new ObjectMapper();
    private final FindingFingerprintService fingerprints = new FindingFingerprintService();

    @Test
    void producesOneSqlGroupPreservesThreeEnginesAndRedactsEveryDownloadArtifact() throws Exception {
        Path root = Files.createDirectories(temporaryDirectory.resolve("job"));
        for (String engine : List.of("semgrep", "findsecbugs", "codeql")) {
            Path raw = Files.createDirectories(root.resolve("raw").resolve(engine));
            Files.writeString(raw.resolve("report.json"), "{\"message\":\"" + EXACT_SECRET + " " + CANARY + "\"}");
        }
        Path logs = Files.createDirectories(root.resolve("logs/engines"));
        Files.writeString(logs.resolve("build.log"), "password=" + EXACT_SECRET + " " + CANARY);
        Files.createDirectories(root.resolve("source"));
        Files.writeString(root.resolve("source/DoNotArchive.java"), "class DoNotArchive {}");
        Path failedCodeqlDatabase = Files.createDirectories(root.resolve("raw/codeql/database/src"));
        Files.writeString(failedCodeqlDatabase.resolve("Captured.java"), "class MustNeverLeaveTheJob {}");

        Finding semgrep = sqlFinding("semgrep", 20, 70, null);
        Finding findsecbugs = sqlFinding("findsecbugs", 20, 70, null);
        Finding codeql = sqlFinding("codeql", 20, 70, null);
        Finding suppressed = sqlFinding("semgrep", 30, 90,
                new FindingSuppression("legacy-query", "accepted " + EXACT_SECRET, null));
        ScanCoverage coverage = new ScanCoverage(1, 1, 1, List.of("**/target/**"), List.of(
                engine("semgrep", EngineStatus.SUCCEEDED, 2, ""),
                engine("findsecbugs", EngineStatus.SUCCEEDED, 1, ""),
                engine("codeql", EngineStatus.PARTIAL, 1, "PARTIAL_QUERY_RESULTS")));
        ReportInput input = new ReportInput(UUID.randomUUID(), ScanProfile.DEEP,
                ScanStatus.COMPLETED_WITH_ERRORS, START, START.plusSeconds(5),
                Map.of("type", "SVN", "url", "https://alice:" + EXACT_SECRET + "@svn.example/repo"),
                List.of(semgrep, findsecbugs, codeql, suppressed), coverage,
                Map.of("components", 428, "vulnerableComponents", 0), Map.of("status", "SUCCEEDED"),
                Map.of("mavenVersion", "3.9.12", "tools", List.of(), "rules", List.of(), "databases", List.of()),
                List.of("**/target/**"), List.of("warning " + EXACT_SECRET),
                "sha256:" + "0".repeat(64));

        ReportBundle bundle = new ReportGenerator().generate(input, root,
                ReportGenerationOptions.withSensitiveValues(List.of(EXACT_SECRET)));

        JsonNode report = json.readTree(bundle.json().toFile());
        assertEquals(1, report.path("summary").path("uniqueFindingCount").asInt());
        assertEquals(4, report.path("summary").path("rawHitCount").asInt());
        assertEquals(1, report.path("summary").path("suppressedCount").asInt());
        assertEquals(3, report.path("findings").get(0).path("evidence").size());
        assertEquals(428, report.path("summary").path("sbom").path("components").asInt());

        JsonNode sarif = json.readTree(bundle.sarif().toFile());
        assertEquals(1, sarif.path("runs").get(0).path("results").size());
        assertEquals(3, sarif.path("runs").get(0).path("results").get(0).path("codeFlows").size());
        assertEquals(1, sarif.path("runs").get(0).path("invocations").get(0)
                .path("toolExecutionNotifications").size());

        String html = Files.readString(bundle.html());
        assertTrue(html.contains("已抑制问题"));
        assertTrue(html.contains("引擎失败或跳过不等于零问题"));
        assertFalse(html.contains("<script"));

        assertNoSecret(root);
        try (ZipFile archive = new ZipFile(bundle.archive().toFile())) {
            assertTrue(archive.getEntry("manifest.json") != null);
            assertTrue(archive.getEntry("raw/semgrep/report.json") != null);
            assertTrue(archive.getEntry("logs/engines/build.log") != null);
            assertTrue(archive.getEntry("source/DoNotArchive.java") == null);
            assertTrue(archive.getEntry("raw/codeql/database/src/Captured.java") == null);
            var entries = archive.entries();
            while (entries.hasMoreElements()) {
                var entry = entries.nextElement();
                if (!entry.isDirectory()) {
                    String text = new String(archive.getInputStream(entry).readAllBytes(), StandardCharsets.UTF_8);
                    assertFalse(text.contains(EXACT_SECRET), entry.getName());
                    assertFalse(text.contains(CANARY), entry.getName());
                }
            }
        }
    }

    @Test
    void refusesMissingRawEvidenceAndImmutableReportRevision() throws Exception {
        Path root = Files.createDirectories(temporaryDirectory.resolve("missing"));
        ReportInput missing = input(List.of(sqlFinding("semgrep", 20, 70, null)),
                List.of(engine("semgrep", EngineStatus.SUCCEEDED, 1, "")));
        assertThrows(IOException.class, () -> new ReportGenerator().generate(missing, root));

        Path completeRoot = Files.createDirectories(temporaryDirectory.resolve("complete"));
        Path raw = Files.createDirectories(completeRoot.resolve("raw/semgrep"));
        Files.writeString(raw.resolve("report.json"), "{}");
        ReportInput valid = input(List.of(sqlFinding("semgrep", 20, 70, null)),
                List.of(engine("semgrep", EngineStatus.SUCCEEDED, 1, "")));
        ReportGenerator generator = new ReportGenerator();
        generator.generate(valid, completeRoot);
        assertThrows(IOException.class, () -> generator.generate(valid, completeRoot));
    }

    private ReportInput input(List<Finding> findings, List<EngineCoverage> engines) {
        return new ReportInput(UUID.randomUUID(), ScanProfile.QUICK, ScanStatus.COMPLETED, START,
                START.plusSeconds(2), Map.of(), findings, new ScanCoverage(1, 0, 1, List.of(), engines),
                Map.of(), Map.of(), Map.of(), List.of(), List.of(), "sha256:" + "0".repeat(64));
    }

    private EngineCoverage engine(String id, EngineStatus status, long hits, String reason) {
        return new EngineCoverage(id, status, 1, 1, 1, hits, Duration.ofSeconds(1), reason,
                "raw/" + id + "/report.json");
    }

    private Finding sqlFinding(String engine, int sourceLine, int sinkLine, FindingSuppression suppression) {
        SourceLocation source = new SourceLocation("src/main/java/UserController.java", sourceLine, 1, sourceLine, 10);
        SourceLocation sink = new SourceLocation("src/main/java/UserController.java", sinkLine, 1, sinkLine, 20);
        DataFlow flow = new DataFlow(engine, List.of(
                new DataFlowNode(0, DataFlowNode.Kind.SOURCE, source, "HTTP parameter"),
                new DataFlowNode(1, DataFlowNode.Kind.SINK, sink, "Statement.execute")));
        var fingerprint = fingerprints.source("SQL_INJECTION", sink.path(), "UserController.search",
                "Statement.execute", "SQL injection", "statement.execute(query)");
        FindingEvidence evidence = new FindingEvidence(engine, "1.0", "sql-rule", "HIGH",
                "raw/" + engine + "/report.json", engine + "-" + sinkLine, Map.of("sinkSymbol", "Statement.execute"));
        return new Finding(fingerprint.findingId() + "-" + engine + "-" + sinkLine, fingerprint.value(), 1,
                IssueCategory.WEB_SECURITY, Severity.P1, Confidence.HIGH, "SQL_INJECTION", "SQL注入",
                "SQL injection", "用户输入进入SQL", "message " + EXACT_SECRET, "数据泄露",
                "使用参数化查询", "app", sink,
                new CodeSnippet(sinkLine, sinkLine, List.of(sinkLine), "query=" + CANARY, false),
                new VulnerabilityIdentifiers(List.of("CWE-89"), List.of(), List.of(), List.of()), null,
                List.of(flow), List.of(evidence), suppression, ReviewState.UNREVIEWED);
    }

    private void assertNoSecret(Path root) throws Exception {
        try (var paths = Files.walk(root)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) {
                if (path.toString().endsWith(".zip")) {
                    continue;
                }
                String text = Files.readString(path);
                assertFalse(text.contains(EXACT_SECRET), path.toString());
                assertFalse(text.contains(CANARY), path.toString());
            }
        }
    }
}
