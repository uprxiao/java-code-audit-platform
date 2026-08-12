package io.github.uprxiao.audit.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.finding.CodeSnippet;
import io.github.uprxiao.audit.finding.Confidence;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingEvidence;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ReviewState;
import io.github.uprxiao.audit.finding.ScanCoverage;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.ScanStatus;
import io.github.uprxiao.audit.finding.Severity;
import io.github.uprxiao.audit.finding.SourceLocation;
import io.github.uprxiao.audit.finding.VulnerabilityIdentifiers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReportGeneratorTest {

    @TempDir
    Path temporaryDirectory;

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void generatesSchemaValidOfflineBundleWithConsistentCountsAndHashes() throws Exception {
        Path jobRoot = Files.createDirectories(temporaryDirectory.resolve("job"));
        Path raw = Files.createDirectories(jobRoot.resolve("raw/semgrep"));
        Files.writeString(raw.resolve("report.json"), "{\"results\":[]}");
        Files.writeString(Files.createDirectories(raw.resolve("home/.semgrep")).resolve("settings.yml"),
                "anonymous_user_id: must-not-leave-job");
        Files.writeString(Files.createDirectories(raw.resolve("cache")).resolve("index"), "cache-data");
        Path logs = Files.createDirectories(jobRoot.resolve("logs/engines"));
        Files.writeString(logs.resolve("semgrep.log"), "done");
        UUID scanId = UUID.fromString("00000000-0000-0000-0000-000000000123");
        EngineCoverage engine = new EngineCoverage("semgrep", EngineStatus.SUCCEEDED,
                1, 1, 1, 1, Duration.ofSeconds(2), "", "raw/semgrep/report.json");
        ScanCoverage coverage = new ScanCoverage(1, 0, 1, List.of("**/target/**"), List.of(engine));
        ReportInput input = new ReportInput(
                scanId, ScanProfile.QUICK, ScanStatus.COMPLETED,
                Instant.parse("2026-08-12T00:00:00Z"), Instant.parse("2026-08-12T00:00:03Z"),
                Map.of("type", "ZIP", "sha256", "abc"),
                List.of(finding()), coverage,
                Map.of("components", 0, "vulnerableComponents", 0),
                Map.of("status", "NOT_REQUIRED"),
                Map.of(
                        "mavenVersion", "3.9.12",
                        "tools", List.of(Map.of("id", "semgrep", "version", "1.170.0")),
                        "rules", List.of(Map.of("id", "java-audit", "version", "1")),
                        "databases", List.of()),
                List.of("**/target/**"), List.of(), "sha256:" + "0".repeat(64));

        ReportBundle bundle = new ReportGenerator().generate(input, jobRoot);

        assertTrue(Files.isRegularFile(bundle.html()));
        assertTrue(Files.isRegularFile(bundle.json()));
        assertTrue(Files.isRegularFile(bundle.sarif()));
        assertTrue(Files.isRegularFile(bundle.coverage()));
        assertTrue(Files.isRegularFile(bundle.manifest()));
        assertTrue(Files.isRegularFile(bundle.archive()));

        JsonNode report = json.readTree(bundle.json().toFile());
        assertEquals(1, report.path("summary").path("uniqueFindingCount").asInt());
        assertEquals(1, report.path("summary").path("rawHitCount").asInt());
        assertEquals(1, sum(report.path("summary").path("severity")));
        assertEquals(1, sum(report.path("summary").path("categories")));
        assertEquals(12, report.path("summary").path("categories").size());

        String html = Files.readString(bundle.html());
        assertFalse(html.contains("<script>alert('x')</script>"));
        assertTrue(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
        assertFalse(html.contains("https://cdn"));
        assertTrue(html.contains("不依赖AI"));

        JsonNode sarif = json.readTree(bundle.sarif().toFile());
        assertEquals("2.1.0", sarif.path("version").asText());
        assertEquals(1, sarif.path("runs").get(0).path("results").size());

        JsonNode manifest = json.readTree(bundle.manifest().toFile());
        Set<String> manifestPaths = new HashSet<>();
        for (JsonNode file : manifest.path("files")) {
            manifestPaths.add(file.path("path").asText());
            Path actual = jobRoot.resolve(file.path("path").asText());
            assertEquals(file.path("size").asLong(), Files.size(actual));
            assertEquals(file.path("sha256").asText(), sha256(actual));
        }
        assertFalse(manifestPaths.contains("raw/semgrep/home/.semgrep/settings.yml"));
        assertFalse(manifestPaths.contains("raw/semgrep/cache/index"));

        Set<String> entries = new HashSet<>();
        try (ZipFile archive = new ZipFile(bundle.archive().toFile())) {
            archive.stream().forEach(entry -> entries.add(entry.getName()));
        }
        assertTrue(entries.contains("report.html"));
        assertTrue(entries.contains("report.json"));
        assertTrue(entries.contains("manifest.json"));
        assertTrue(entries.contains("raw/semgrep/report.json"));
        assertTrue(entries.contains("logs/engines/semgrep.log"));
        assertFalse(entries.contains("raw/semgrep/home/.semgrep/settings.yml"));
        assertFalse(entries.contains("raw/semgrep/cache/index"));
        assertTrue(entries.stream().noneMatch(name -> name.contains("source") || name.contains("workspace")
                || name.contains("target") || name.contains("codeql-db")));
    }

    @Test
    void rejectsAReportWhoseRawCountCannotExplainNormalizedFindings() {
        EngineCoverage engine = new EngineCoverage("semgrep", EngineStatus.SUCCEEDED,
                1, 1, 1, 0, Duration.ZERO, "", "raw/semgrep/report.json");
        ReportInput input = new ReportInput(
                UUID.randomUUID(), ScanProfile.QUICK, ScanStatus.COMPLETED,
                Instant.parse("2026-08-12T00:00:00Z"), Instant.parse("2026-08-12T00:00:01Z"),
                Map.of(), List.of(finding()), new ScanCoverage(1, 0, 1, List.of(), List.of(engine)),
                Map.of(), Map.of(), Map.of(), List.of(), List.of(), "sha256:" + "0".repeat(64));

        assertThrows(IllegalArgumentException.class,
                () -> new ReportGenerator().generate(input, temporaryDirectory.resolve("bad-job")));
    }

    private Finding finding() {
        FindingEvidence evidence = new FindingEvidence(
                "semgrep", "1.170.0", "java.sql.concatenated-query", "ERROR",
                "raw/semgrep/report.json", "1", Map.of());
        return new Finding(
                "F-123", "sha256:" + "1".repeat(64), 1,
                IssueCategory.WEB_SECURITY, Severity.P1, Confidence.HIGH, "SQL_INJECTION",
                "<script>alert('x')</script>", "SQL concatenation", "动态SQL存在风险", "original message",
                "数据可能泄露", "使用参数化查询", "app",
                new SourceLocation("src/main/java/App.java", 7, 1, 7, 10),
                new CodeSnippet(2, 12, List.of(7), "String value = \"<script>alert('x')</script>\";", false),
                new VulnerabilityIdentifiers(List.of("CWE-89"), List.of(), List.of(), List.of()),
                null, List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    private int sum(JsonNode node) {
        int total = 0;
        for (JsonNode value : node) {
            total += value.asInt();
        }
        return total;
    }

    private String sha256(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }
}
