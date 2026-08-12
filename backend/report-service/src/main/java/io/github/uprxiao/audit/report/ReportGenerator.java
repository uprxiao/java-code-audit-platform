package io.github.uprxiao.audit.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ScanCoverage;
import io.github.uprxiao.audit.finding.Severity;
import io.github.uprxiao.audit.storage.AtomicFileWriter;
import io.github.uprxiao.audit.storage.NioAtomicFileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public final class ReportGenerator {

    private final ObjectMapper json;
    private final AtomicFileWriter writer;
    private final JsonSchemaValidationService schemas;
    private final ReportArchiveBuilder archives;

    public ReportGenerator() {
        this(defaultMapper(), new NioAtomicFileWriter(), new JsonSchemaValidationService(), new ReportArchiveBuilder());
    }

    ReportGenerator(
            ObjectMapper json,
            AtomicFileWriter writer,
            JsonSchemaValidationService schemas,
            ReportArchiveBuilder archives) {
        this.json = Objects.requireNonNull(json, "json");
        this.writer = Objects.requireNonNull(writer, "writer");
        this.schemas = Objects.requireNonNull(schemas, "schemas");
        this.archives = Objects.requireNonNull(archives, "archives");
    }

    public ReportBundle generate(ReportInput input, Path jobRoot) throws IOException {
        Objects.requireNonNull(input, "input");
        Path root = jobRoot.toAbsolutePath().normalize();
        Path reportDirectory = root.resolve("report");
        Files.createDirectories(reportDirectory);
        Path reportJson = reportDirectory.resolve("report.json");
        Path reportHtml = reportDirectory.resolve("report.html");
        Path reportSarif = reportDirectory.resolve("report.sarif");
        Path coverageJson = reportDirectory.resolve("coverage.json");
        Path manifestJson = reportDirectory.resolve("manifest.json");

        List<Finding> active = input.findings().stream().filter(finding -> !finding.suppressed()).toList();
        List<Finding> suppressed = input.findings().stream().filter(Finding::suppressed).toList();
        Map<String, Object> coverage = coverageDocument(input.coverage());
        List<Map<String, Object>> engines = engineDocuments(input.coverage().engines());
        ReportSummary summary = summary(input, active, suppressed);
        validateInvariants(summary, active, suppressed);
        AuditReport report = new AuditReport(
                "1.0",
                orderedMap(
                        "scanId", input.scanId().toString(),
                        "profile", input.profile().name(),
                        "status", input.status().name(),
                        "createdAt", input.createdAt().toString(),
                        "completedAt", input.completedAt().toString()),
                summary,
                coverage,
                active,
                suppressed,
                input.sbomSummary(),
                engines,
                input.build(),
                input.toolchain(),
                input.exclusions(),
                input.warnings(),
                List.of(
                        Map.of("path", "report.html", "type", "text/html"),
                        Map.of("path", "report.json", "type", "application/json"),
                        Map.of("path", "report.sarif", "type", "application/sarif+json"),
                        Map.of("path", "coverage.json", "type", "application/json"),
                        Map.of("path", "manifest.json", "type", "application/json")));

        writeJson(reportJson, report);
        writer.write(reportHtml, html(input, report).getBytes(StandardCharsets.UTF_8));
        writeJson(reportSarif, sarif(input, active));
        writeJson(coverageJson, coverage);
        schemas.validate("report", reportJson);
        schemas.validate("coverage", coverageJson);

        Map<String, Object> manifest = manifest(input, List.of(reportHtml, reportJson, reportSarif, coverageJson));
        writeJson(manifestJson, manifest);
        schemas.validate("manifest", manifestJson);

        Path archive = root.resolve("archive").resolve("scan-report-" + input.scanId() + ".zip");
        archives.build(input.scanId(), root, archive);
        return new ReportBundle(reportHtml, reportJson, reportSarif, coverageJson, manifestJson, archive);
    }

    private ReportSummary summary(ReportInput input, List<Finding> active, List<Finding> suppressed) {
        Map<Severity, Integer> severity = new EnumMap<>(Severity.class);
        for (Severity value : Severity.values()) {
            severity.put(value, 0);
        }
        Map<IssueCategory, Integer> categories = new EnumMap<>(IssueCategory.class);
        for (IssueCategory value : IssueCategory.values()) {
            categories.put(value, 0);
        }
        active.forEach(finding -> {
            severity.compute(finding.severity(), (ignored, count) -> count + 1);
            categories.compute(finding.category(), (ignored, count) -> count + 1);
        });
        Map<String, Integer> engineCounts = new LinkedHashMap<>();
        for (EngineStatus status : EngineStatus.values()) {
            if (status.isTerminal()) {
                engineCounts.put(status.name().toLowerCase(Locale.ROOT), 0);
            }
        }
        input.coverage().engines().forEach(engine -> engineCounts.compute(
                engine.status().name().toLowerCase(Locale.ROOT), (ignored, count) -> count == null ? 1 : count + 1));
        long rawHitCount = input.coverage().engines().stream().mapToLong(EngineCoverage::rawHitCount).sum();
        Duration duration = Duration.between(input.createdAt(), input.completedAt());
        return new ReportSummary(
                active.size(),
                rawHitCount,
                suppressed.size(),
                enumCounts(severity),
                enumCounts(categories),
                Map.copyOf(engineCounts),
                Map.of(
                        "discovered", input.coverage().modulesDiscovered(),
                        "built", input.coverage().modulesBuilt(),
                        "scanned", input.coverage().modulesScanned()),
                Map.of(
                        "components", number(input.sbomSummary().get("components")),
                        "vulnerableComponents", number(input.sbomSummary().get("vulnerableComponents"))),
                Math.max(0, duration.toMillis()));
    }

    private void validateInvariants(ReportSummary summary, List<Finding> active, List<Finding> suppressed) {
        int severityTotal = summary.severity().values().stream().mapToInt(Integer::intValue).sum();
        int categoryTotal = summary.categories().values().stream().mapToInt(Integer::intValue).sum();
        if (severityTotal != active.size() || categoryTotal != active.size()) {
            throw new IllegalArgumentException("report severity/category totals are inconsistent");
        }
        if (summary.rawHitCount() < active.size() + suppressed.size()) {
            throw new IllegalArgumentException("raw finding count is lower than normalized finding count");
        }
        if (active.stream().anyMatch(finding -> finding.evidence().isEmpty())) {
            throw new IllegalArgumentException("every active finding must retain raw evidence");
        }
    }

    private Map<String, Object> coverageDocument(ScanCoverage coverage) {
        return orderedMap(
                "schemaVersion", 1,
                "project", orderedMap(
                        "modulesDiscovered", coverage.modulesDiscovered(),
                        "modulesBuilt", coverage.modulesBuilt(),
                        "modulesScanned", coverage.modulesScanned(),
                        "excludedPaths", coverage.excludedPaths()),
                "engines", engineDocuments(coverage.engines()));
    }

    private List<Map<String, Object>> engineDocuments(List<EngineCoverage> engines) {
        return engines.stream().map(engine -> orderedMap(
                "engine", engine.engine(),
                "status", engine.status().name(),
                "modulesDiscovered", engine.modulesDiscovered(),
                "applicableModules", engine.modulesApplicable(),
                "scannedModules", engine.modulesScanned(),
                "rawHitCount", engine.rawHitCount(),
                "durationMs", engine.duration().toMillis(),
                "reasonCode", engine.reasonCode(),
                "artifact", engine.artifact())).toList();
    }

    private Map<String, Object> sarif(ReportInput input, List<Finding> findings) {
        List<Map<String, Object>> results = findings.stream().map(finding -> {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("ruleId", finding.ruleFamily());
            result.put("level", sarifLevel(finding.severity()));
            result.put("message", Map.of("text", firstNonBlank(finding.titleZh(), finding.titleOriginal())));
            if (finding.location() != null) {
                result.put("locations", List.of(Map.of("physicalLocation", Map.of(
                        "artifactLocation", Map.of("uri", finding.location().path()),
                        "region", orderedMap(
                                "startLine", finding.location().startLine(),
                                "startColumn", Math.max(1, finding.location().startColumn()),
                                "endLine", finding.location().endLine(),
                                "endColumn", Math.max(1, finding.location().endColumn()))))));
            }
            result.put("properties", Map.of(
                    "findingId", finding.id(),
                    "fingerprint", finding.fingerprint(),
                    "category", finding.category().name(),
                    "confidence", finding.confidence().name(),
                    "engines", finding.evidence().stream().map(evidence -> evidence.engine()).distinct().toList(),
                    "titleZh", finding.titleZh(),
                    "remediationZh", finding.remediationZh()));
            return Map.copyOf(result);
        }).toList();
        List<Map<String, Object>> notifications = input.coverage().engines().stream()
                .filter(engine -> engine.status() != EngineStatus.SUCCEEDED)
                .map(engine -> Map.<String, Object>of(
                        "level", "warning",
                        "message", Map.of("text", engine.engine() + ": " + engine.reasonCode())))
                .toList();
        Map<String, Object> run = orderedMap(
                "tool", Map.of("driver", Map.of(
                        "name", "Java Code Audit Platform",
                        "version", "0.1.0",
                        "informationUri", "https://github.com/uprxiao/java-code-audit-platform")),
                "invocations", List.of(Map.of(
                        "executionSuccessful", input.status().name().startsWith("COMPLETED"),
                        "toolExecutionNotifications", notifications)),
                "results", results);
        return orderedMap("version", "2.1.0", "$schema",
                "https://json.schemastore.org/sarif-2.1.0.json", "runs", List.of(run));
    }

    private String html(ReportInput input, AuditReport report) {
        StringBuilder findings = new StringBuilder();
        for (Finding finding : report.findings()) {
            findings.append("<article class=\"finding\"><h3>")
                    .append(escape(finding.severity().name())).append(" · ")
                    .append(escape(firstNonBlank(finding.titleZh(), finding.titleOriginal())))
                    .append("</h3><p><strong>分类：</strong>").append(escape(finding.category().name()))
                    .append("　<strong>规则族：</strong>").append(escape(finding.ruleFamily())).append("</p>");
            if (finding.location() != null) {
                findings.append("<p><strong>代码：</strong>").append(escape(finding.location().path()))
                        .append(":").append(finding.location().startLine()).append("</p>");
            }
            findings.append("<p>").append(escape(firstNonBlank(finding.descriptionZh(), finding.messageOriginal())))
                    .append("</p><p><strong>影响：</strong>").append(escape(finding.impactZh()))
                    .append("</p><p><strong>修复：</strong>").append(escape(finding.remediationZh())).append("</p>");
            if (finding.snippet() != null) {
                findings.append("<pre><code>").append(escape(finding.snippet().text())).append("</code></pre>");
            }
            findings.append("<p class=\"evidence\">证据：")
                    .append(escape(String.join(", ", finding.evidence().stream()
                            .map(evidence -> evidence.engine() + "/" + evidence.ruleId()).toList())))
                    .append("</p></article>");
        }
        StringBuilder engineRows = new StringBuilder();
        for (Map<String, Object> engine : report.engines()) {
            engineRows.append("<tr><td>").append(escape(engine.get("engine")))
                    .append("</td><td>").append(escape(engine.get("status")))
                    .append("</td><td>").append(engine.get("rawHitCount"))
                    .append("</td><td>").append(engine.get("durationMs"))
                    .append("</td><td>").append(escape(engine.get("reasonCode"))).append("</td></tr>");
        }
        return """
                <!doctype html><html lang="zh-CN"><head><meta charset="UTF-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>Java代码审计报告</title><style>
                :root{color-scheme:light;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033;background:#f5f7fb}
                body{max-width:1180px;margin:auto;padding:32px}.hero,.card,.finding{background:white;border:1px solid #dfe5ef;border-radius:14px;padding:20px;margin:14px 0;box-shadow:0 4px 18px #1720330d}
                .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.metric{font-size:30px;font-weight:700}.label{color:#637083}table{width:100%%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #e6eaf0;padding:10px}
                .finding h3{margin-top:0}pre{overflow:auto;background:#111827;color:#e5e7eb;border-radius:10px;padding:16px}.evidence{color:#526079}.warning{border-left:5px solid #e59b24}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
                </style></head><body>
                <section class="hero"><h1>Java代码审计报告</h1><p>任务 %s · %s · %s</p></section>
                <section class="grid"><div class="card"><div class="metric">%d</div><div class="label">唯一问题</div></div>
                <div class="card"><div class="metric">%d</div><div class="label">原始命中</div></div>
                <div class="card"><div class="metric">%d</div><div class="label">抑制问题</div></div>
                <div class="card"><div class="metric">%d ms</div><div class="label">总耗时</div></div></section>
                <section class="card warning"><h2>覆盖状态</h2><p>发现模块 %d，完成扫描 %d。引擎失败或跳过不等于零问题。</p></section>
                <section class="card"><h2>严重性统计</h2><p>%s</p><h2>十二类审计统计</h2><p>%s</p></section>
                <section class="card"><h2>引擎执行</h2><table><thead><tr><th>引擎</th><th>状态</th><th>原始命中</th><th>耗时(ms)</th><th>原因</th></tr></thead><tbody>%s</tbody></table></section>
                <section><h2>问题详情</h2>%s</section>
                <footer><p>本报告由确定性扫描器生成，不依赖AI。静态分析可能存在误报和漏报，请结合人工复核。</p></footer>
                </body></html>
                """.formatted(
                escape(input.scanId()), escape(input.profile()), escape(input.status()),
                report.summary().uniqueFindingCount(), report.summary().rawHitCount(), report.summary().suppressedCount(),
                report.summary().durationMs(), input.coverage().modulesDiscovered(), input.coverage().modulesScanned(),
                escape(report.summary().severity()), escape(report.summary().categories()), engineRows, findings);
    }

    private Map<String, Object> manifest(ReportInput input, List<Path> files) throws IOException {
        List<Map<String, Object>> fileEntries = new ArrayList<>();
        for (Path file : files) {
            fileEntries.add(orderedMap(
                    "path", file.getFileName().toString(),
                    "size", Files.size(file),
                    "sha256", sha256(Files.readAllBytes(file))));
        }
        return orderedMap(
                "schemaVersion", 1,
                "scanId", input.scanId().toString(),
                "profile", input.profile().name(),
                "createdAt", input.createdAt().toString(),
                "completedAt", input.completedAt().toString(),
                "source", input.source(),
                "runtime", orderedMap(
                        "javaVersion", System.getProperty("java.version"),
                        "mavenVersion", input.toolchain().getOrDefault("mavenVersion", "unknown"),
                        "os", System.getProperty("os.name"),
                        "architecture", System.getProperty("os.arch")),
                "maven", input.build(),
                "tools", listValue(input.toolchain().get("tools")),
                "rules", listValue(input.toolchain().get("rules")),
                "databases", listValue(input.toolchain().get("databases")),
                "configFingerprint", input.configFingerprint(),
                "report", Map.of("schemaVersion", "1.0", "fingerprintVersion", 1, "parserSchemaVersion", 1),
                "files", fileEntries);
    }

    private void writeJson(Path target, Object value) throws IOException {
        writer.write(target, json.writerWithDefaultPrettyPrinter().writeValueAsBytes(value));
    }

    private String sarifLevel(Severity severity) {
        return switch (severity) {
            case P0, P1 -> "error";
            case P2 -> "warning";
            case P3 -> "note";
        };
    }

    private String firstNonBlank(String first, String second) {
        return first != null && !first.isBlank() ? first : second;
    }

    private int number(Object value) {
        return value instanceof Number number ? number.intValue() : 0;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> listValue(Object value) {
        return value instanceof List<?> list ? (List<Map<String, Object>>) list : List.of();
    }

    private <E extends Enum<E>> Map<String, Integer> enumCounts(Map<E, Integer> values) {
        Map<String, Integer> result = new LinkedHashMap<>();
        values.forEach((key, value) -> result.put(key.name(), value));
        return Map.copyOf(result);
    }

    private String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    private String escape(Object value) {
        String text = String.valueOf(value);
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static ObjectMapper defaultMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    private static Map<String, Object> orderedMap(Object... values) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index += 2) {
            result.put((String) values[index], values[index + 1]);
        }
        return result;
    }
}
