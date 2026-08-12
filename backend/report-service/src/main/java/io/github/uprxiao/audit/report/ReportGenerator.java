package io.github.uprxiao.audit.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.uprxiao.audit.finding.ComponentEvidence;
import io.github.uprxiao.audit.finding.ConservativeFindingDeduplicator;
import io.github.uprxiao.audit.finding.DataFlow;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingEvidence;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ScanCoverage;
import io.github.uprxiao.audit.finding.Severity;
import io.github.uprxiao.audit.storage.AtomicFileWriter;
import io.github.uprxiao.audit.storage.NioAtomicFileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipFile;

public final class ReportGenerator {

    private static final String PLATFORM_VERSION = "0.1.0";

    private final ObjectMapper json;
    private final AtomicFileWriter writer;
    private final JsonSchemaValidationService schemas;
    private final ReportArchiveBuilder archives;
    private final ConservativeFindingDeduplicator deduplicator;
    private final SarifValidationService sarifValidator;

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
        this.deduplicator = new ConservativeFindingDeduplicator();
        this.sarifValidator = new SarifValidationService(json);
    }

    public ReportBundle generate(ReportInput input, Path jobRoot) throws IOException {
        return generate(input, jobRoot, ReportGenerationOptions.defaults());
    }

    public ReportBundle generate(ReportInput original, Path jobRoot, ReportGenerationOptions options) throws IOException {
        Objects.requireNonNull(original, "input");
        Objects.requireNonNull(options, "options");
        Path root = verifiedJobRoot(jobRoot);
        ReportInput input = new ReportInputSanitizer(options.redactor()).sanitize(original);
        ArtifactRedactionService artifactRedaction = new ArtifactRedactionService(options.redactor(), writer);
        if (options.sanitizeRawLogsAndSbom()) {
            artifactRedaction.sanitize(root);
        }

        List<Finding> active = deduplicator.deduplicate(
                input.findings().stream().filter(finding -> !finding.suppressed()).toList()).findings();
        List<Finding> suppressed = deduplicator.deduplicate(
                input.findings().stream().filter(Finding::suppressed).toList()).findings();
        Map<String, Object> coverage = coverageDocument(input.coverage());
        List<Map<String, Object>> engines = engineDocuments(input.coverage().engines());
        ReportSummary summary = summary(input, active, suppressed);
        validateInvariants(summary, active, suppressed, input.coverage());
        validateEvidence(root, active, suppressed);

        Path reportDirectory = root.resolve("report");
        Files.createDirectories(reportDirectory);
        Path reportJson = reportDirectory.resolve("report.json");
        Path reportHtml = reportDirectory.resolve("report.html");
        Path reportSarif = reportDirectory.resolve("report.sarif");
        Path coverageJson = reportDirectory.resolve("coverage.json");
        Path manifestJson = reportDirectory.resolve("manifest.json");
        Path archive = root.resolve("archive").resolve("scan-report-" + input.scanId() + ".zip");
        List<Path> reportTargets = List.of(reportHtml, reportJson, reportSarif, coverageJson, manifestJson);
        ensureImmutableTargetsAbsent(reportTargets);

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
                        artifact("report.html", "text/html"),
                        artifact("report.json", "application/json"),
                        artifact("report.sarif", "application/sarif+json"),
                        artifact("coverage.json", "application/json"),
                        artifact("manifest.json", "application/json")));

        try {
            writeJson(reportJson, report);
            writer.write(reportHtml, html(input, report).getBytes(StandardCharsets.UTF_8));
            writeJson(reportSarif, sarif(input, active));
            writeJson(coverageJson, coverage);
            schemas.validate("report", reportJson);
            schemas.validate("coverage", coverageJson);
            sarifValidator.validate(reportSarif);

            List<Path> manifestedFiles = manifestFiles(root, List.of(reportHtml, reportJson, reportSarif, coverageJson));
            Map<String, Object> manifest = manifest(input, root, manifestedFiles);
            writeJson(manifestJson, manifest);
            schemas.validate("manifest", manifestJson);
            validateManifestHashes(root, manifest);
            List<Path> finalized = new ArrayList<>(manifestedFiles);
            finalized.add(manifestJson);
            artifactRedaction.assertSensitiveValuesAbsent(finalized);

            archives.build(input.scanId(), root, archive);
            validateArchive(archive);
            return new ReportBundle(reportHtml, reportJson, reportSarif, coverageJson, manifestJson, archive);
        } catch (IOException | RuntimeException exception) {
            for (Path target : reportTargets) {
                Files.deleteIfExists(target);
            }
            Files.deleteIfExists(archive);
            throw exception;
        }
    }

    private ReportSummary summary(ReportInput input, List<Finding> active, List<Finding> suppressed) {
        Map<Severity, Integer> severity = zeroCounts(Severity.class);
        Map<IssueCategory, Integer> categories = zeroCounts(IssueCategory.class);
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
                active.size(), rawHitCount, suppressed.size(), enumCounts(severity), enumCounts(categories),
                Map.copyOf(engineCounts),
                Map.of("discovered", input.coverage().modulesDiscovered(), "built", input.coverage().modulesBuilt(),
                        "scanned", input.coverage().modulesScanned()),
                Map.of("components", number(input.sbomSummary().get("components")),
                        "vulnerableComponents", number(input.sbomSummary().get("vulnerableComponents"))),
                Math.max(0, duration.toMillis()));
    }

    private <E extends Enum<E>> Map<E, Integer> zeroCounts(Class<E> type) {
        Map<E, Integer> result = new EnumMap<>(type);
        for (E value : type.getEnumConstants()) {
            result.put(value, 0);
        }
        return result;
    }

    private void validateInvariants(
            ReportSummary summary, List<Finding> active, List<Finding> suppressed, ScanCoverage coverage) {
        int severityTotal = summary.severity().values().stream().mapToInt(Integer::intValue).sum();
        int categoryTotal = summary.categories().values().stream().mapToInt(Integer::intValue).sum();
        if (severityTotal != active.size() || categoryTotal != active.size()
                || summary.uniqueFindingCount() != active.size() || summary.suppressedCount() != suppressed.size()) {
            throw new IllegalArgumentException("report severity/category/finding totals are inconsistent");
        }
        if (summary.rawHitCount() < active.size() + suppressed.size()) {
            throw new IllegalArgumentException("raw finding count is lower than normalized finding count");
        }
        if (active.stream().anyMatch(finding -> finding.evidence().isEmpty())
                || suppressed.stream().anyMatch(finding -> finding.evidence().isEmpty())) {
            throw new IllegalArgumentException("every finding must retain raw evidence");
        }
        if (coverage.engines().stream().anyMatch(engine -> !engine.status().isTerminal())) {
            throw new IllegalArgumentException("final reports require a terminal status for every engine");
        }
    }

    private void validateEvidence(Path root, List<Finding> active, List<Finding> suppressed) throws IOException {
        for (Finding finding : java.util.stream.Stream.concat(active.stream(), suppressed.stream()).toList()) {
            for (FindingEvidence evidence : finding.evidence()) {
                Path artifact = root.resolve(evidence.rawArtifact()).normalize();
                if (!artifact.startsWith(root) || Files.isSymbolicLink(artifact)
                        || !Files.isRegularFile(artifact, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("finding evidence does not reference an existing safe raw artifact: "
                            + evidence.rawArtifact());
                }
            }
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
                "engine", engine.engine(), "status", engine.status().name(),
                "modulesDiscovered", engine.modulesDiscovered(),
                "applicableModules", engine.modulesApplicable(),
                "scannedModules", engine.modulesScanned(), "rawHitCount", engine.rawHitCount(),
                "durationMs", engine.duration().toMillis(), "reasonCode", engine.reasonCode(),
                "artifact", engine.artifact())).toList();
    }

    private Map<String, Object> sarif(ReportInput input, List<Finding> findings) {
        List<Map<String, Object>> results = findings.stream().map(this::sarifResult).toList();
        List<Map<String, Object>> notifications = input.coverage().engines().stream()
                .filter(engine -> engine.status() != EngineStatus.SUCCEEDED)
                .map(engine -> orderedMap(
                        "level", engine.status() == EngineStatus.PARTIAL ? "warning" : "error",
                        "message", Map.of("text", engine.engine() + ": " + firstNonBlank(engine.reasonCode(),
                                engine.status().name()))))
                .toList();
        List<Map<String, Object>> rules = findings.stream().collect(java.util.stream.Collectors.toMap(
                        Finding::ruleFamily,
                        finding -> orderedMap("id", finding.ruleFamily(), "name",
                                firstNonBlank(finding.titleOriginal(), finding.titleZh()),
                                "properties", Map.of("category", finding.category().name(),
                                        "cwe", finding.identifiers().cwe())),
                        (left, right) -> left, LinkedHashMap::new)).values().stream().toList();
        Map<String, Object> run = orderedMap(
                "tool", Map.of("driver", orderedMap(
                        "name", "Java Code Audit Platform", "version", PLATFORM_VERSION,
                        "informationUri", "https://github.com/uprxiao/java-code-audit-platform", "rules", rules)),
                "invocations", List.of(Map.of(
                        "executionSuccessful", input.status().name().startsWith("COMPLETED"),
                        "toolExecutionNotifications", notifications)),
                "results", results);
        return orderedMap("version", "2.1.0", "$schema",
                "https://json.schemastore.org/sarif-2.1.0.json", "runs", List.of(run));
    }

    private Map<String, Object> sarifResult(Finding finding) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ruleId", finding.ruleFamily());
        result.put("level", sarifLevel(finding.severity()));
        result.put("message", Map.of("text", firstNonBlank(finding.titleOriginal(), finding.titleZh())));
        if (finding.location() != null) {
            result.put("locations", List.of(sarifLocation(finding.location())));
        }
        if (!finding.dataFlows().isEmpty()) {
            result.put("codeFlows", finding.dataFlows().stream().map(this::sarifCodeFlow).toList());
        }
        result.put("partialFingerprints", Map.of("javaAudit/v1", finding.fingerprint()));
        result.put("properties", orderedMap(
                "findingId", finding.id(), "fingerprint", finding.fingerprint(),
                "category", finding.category().name(), "confidence", finding.confidence().name(),
                "engines", finding.evidence().stream().map(FindingEvidence::engine).distinct().toList(),
                "evidence", finding.evidence().stream().map(evidence -> orderedMap(
                        "engine", evidence.engine(), "ruleId", evidence.ruleId(),
                        "rawArtifact", evidence.rawArtifact(), "rawItemId", evidence.rawItemId())).toList(),
                "cwe", finding.identifiers().cwe(), "cve", finding.identifiers().cve(),
                "titleZh", finding.titleZh(), "remediationZh", finding.remediationZh()));
        return Map.copyOf(result);
    }

    private Map<String, Object> sarifCodeFlow(DataFlow flow) {
        List<Map<String, Object>> locations = flow.nodes().stream().map(node -> orderedMap(
                "location", sarifLocation(node.location()),
                "kinds", List.of(node.kind().name()), "nestingLevel", node.index(),
                "message", Map.of("text", node.label()))).toList();
        return Map.of("message", Map.of("text", "Data flow from " + flow.engine()),
                "threadFlows", List.of(Map.of("locations", locations)));
    }

    private Map<String, Object> sarifLocation(io.github.uprxiao.audit.finding.SourceLocation location) {
        return Map.of("physicalLocation", Map.of(
                "artifactLocation", Map.of("uri", location.path()),
                "region", orderedMap("startLine", location.startLine(),
                        "startColumn", Math.max(1, location.startColumn()), "endLine", location.endLine(),
                        "endColumn", Math.max(1, location.endColumn()))));
    }

    private String html(ReportInput input, AuditReport report) {
        StringBuilder findings = new StringBuilder();
        report.findings().stream().sorted(Comparator.comparing(Finding::severity)
                .thenComparing(Finding::category).thenComparing(Finding::fingerprint))
                .forEach(finding -> findings.append(findingHtml(finding, false)));
        StringBuilder suppressed = new StringBuilder();
        report.suppressedFindings().forEach(finding -> suppressed.append(findingHtml(finding, true)));
        StringBuilder engineRows = new StringBuilder();
        for (Map<String, Object> engine : report.engines()) {
            engineRows.append("<tr><td>").append(escape(engine.get("engine")))
                    .append("</td><td>").append(escape(engine.get("status")))
                    .append("</td><td>").append(engine.get("rawHitCount"))
                    .append("</td><td>").append(engine.get("durationMs"))
                    .append("</td><td>").append(escape(engine.get("reasonCode"))).append("</td></tr>");
        }
        String warnings = report.warnings().isEmpty() ? "<p>无</p>" : "<ul>" + report.warnings().stream()
                .map(warning -> "<li>" + escape(warning) + "</li>").collect(java.util.stream.Collectors.joining()) + "</ul>";
        return """
                <!doctype html><html lang="zh-CN"><head><meta charset="UTF-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>Java代码审计报告</title><style>
                :root{color-scheme:light;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#172033;background:#f5f7fb}
                body{max-width:1180px;margin:auto;padding:32px}.hero,.card,.finding{background:white;border:1px solid #dfe5ef;border-radius:14px;padding:20px;margin:14px 0;box-shadow:0 4px 18px #1720330d}
                .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.metric{font-size:30px;font-weight:700}.label{color:#637083}table{width:100%%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #e6eaf0;padding:10px}
                .finding h3{margin-top:0}pre{overflow:auto;background:#111827;color:#e5e7eb;border-radius:10px;padding:16px}.evidence{color:#526079}.warning{border-left:5px solid #e59b24}.suppressed{opacity:.8;border-left:5px solid #64748b}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
                </style></head><body>
                <section class="hero"><h1>Java代码审计报告</h1><p>任务 %s · %s · %s</p></section>
                <section class="grid"><div class="card"><div class="metric">%d</div><div class="label">唯一问题</div></div>
                <div class="card"><div class="metric">%d</div><div class="label">原始命中</div></div>
                <div class="card"><div class="metric">%d</div><div class="label">抑制问题</div></div>
                <div class="card"><div class="metric">%d ms</div><div class="label">总耗时</div></div></section>
                <section class="card warning"><h2>覆盖与失败状态</h2><p>发现模块 %d，构建 %d，完成扫描 %d。引擎失败或跳过不等于零问题。</p></section>
                <section class="card"><h2>严重性统计</h2><p>%s</p><h2>十二类审计统计</h2><p>%s</p></section>
                <section class="card"><h2>引擎执行</h2><table><thead><tr><th>引擎</th><th>状态</th><th>原始命中</th><th>耗时(ms)</th><th>原因</th></tr></thead><tbody>%s</tbody></table></section>
                <section class="card"><h2>警告</h2>%s<h2>路径排除</h2><p>%s</p><h2>SBOM/供应链资产</h2><pre><code>%s</code></pre></section>
                <section class="card"><h2>构建、工具、规则与数据库</h2><h3>Maven构建</h3><pre><code>%s</code></pre><h3>工具链</h3><pre><code>%s</code></pre></section>
                <section><h2>有效问题详情</h2>%s</section>
                <section><h2>已抑制问题</h2>%s</section>
                <footer><p>本报告由确定性扫描器生成，不依赖AI。静态分析可能存在误报和漏报，且不代表漏洞可达或可利用，请结合人工复核。</p></footer>
                </body></html>
                """.formatted(
                escape(input.scanId()), escape(input.profile()), escape(input.status()),
                report.summary().uniqueFindingCount(), report.summary().rawHitCount(), report.summary().suppressedCount(),
                report.summary().durationMs(), input.coverage().modulesDiscovered(), input.coverage().modulesBuilt(),
                input.coverage().modulesScanned(), escape(report.summary().severity()),
                escape(report.summary().categories()), engineRows, warnings, escape(report.exclusions()),
                escape(report.sbomSummary()), escape(report.build()), escape(report.toolchain()), findings,
                suppressed.length() == 0 ? "<p>无</p>" : suppressed);
    }

    private String findingHtml(Finding finding, boolean suppressed) {
        StringBuilder result = new StringBuilder("<article class=\"finding")
                .append(suppressed ? " suppressed\">" : "\">").append("<h3>")
                .append(escape(finding.severity().name())).append(" · ")
                .append(escape(firstNonBlank(finding.titleZh(), finding.titleOriginal()))).append("</h3>")
                .append("<p><strong>分类：</strong>").append(escape(finding.category().name()))
                .append("　<strong>规则族：</strong>").append(escape(finding.ruleFamily())).append("</p>");
        if (finding.location() != null) {
            result.append("<p><strong>代码：</strong>").append(escape(finding.location().path()))
                    .append(":").append(finding.location().startLine()).append("</p>");
        }
        result.append("<p>").append(escape(firstNonBlank(finding.descriptionZh(), finding.messageOriginal())))
                .append("</p><p><strong>影响：</strong>").append(escape(finding.impactZh()))
                .append("</p><p><strong>修复：</strong>").append(escape(finding.remediationZh())).append("</p>");
        if (!finding.titleOriginal().isBlank() || !finding.messageOriginal().isBlank()) {
            result.append("<p><strong>引擎原文：</strong>")
                    .append(escape(firstNonBlank(finding.titleOriginal(), finding.messageOriginal())))
                    .append("</p>");
        }
        if (finding.snippet() != null) {
            result.append("<pre><code>").append(escape(finding.snippet().text())).append("</code></pre>");
        }
        if (finding.component() != null) {
            result.append("<p><strong>组件：</strong>").append(escape(componentText(finding.component()))).append("</p>");
        }
        if (!finding.dataFlows().isEmpty()) {
            result.append("<ol>");
            finding.dataFlows().forEach(flow -> flow.nodes().forEach(node -> result.append("<li>")
                    .append(escape(flow.engine())).append(" / ").append(escape(node.kind())).append(" / ")
                    .append(escape(node.location().path())).append(":").append(node.location().startLine())
                    .append(" / ").append(escape(node.label())).append("</li>")));
            result.append("</ol>");
        }
        result.append("<p class=\"evidence\">证据：")
                .append(escape(String.join(", ", finding.evidence().stream()
                        .map(evidence -> evidence.engine() + "/" + evidence.ruleId() + " -> " + evidence.rawArtifact())
                        .toList()))).append("</p>");
        if (suppressed && finding.suppression() != null) {
            result.append("<p><strong>抑制：</strong>").append(escape(finding.suppression().ruleId()))
                    .append(" · ").append(escape(finding.suppression().reason())).append("</p>");
        }
        return result.append("</article>").toString();
    }

    private String componentText(ComponentEvidence component) {
        return component.purl() + " / path=" + component.dependencyPath() + " / fixed=" + component.fixedVersions();
    }

    private List<Path> manifestFiles(Path root, List<Path> reports) throws IOException {
        Set<Path> files = new TreeSet<>(Comparator.comparing(path -> portable(root.relativize(path))));
        files.addAll(reports);
        for (String name : List.of("raw", "logs", "sbom")) {
            Path directory = root.resolve(name);
            if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
                continue;
            }
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.toList()) {
                    if (Files.isSymbolicLink(path)) {
                        throw new IOException("symbolic link is forbidden in manifest inputs: " + path);
                    }
                    if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                        String relative = portable(root.relativize(path));
                        if (!forbiddenReportArtifact(relative)) {
                            files.add(path);
                        }
                    }
                }
            }
        }
        return List.copyOf(files);
    }

    private Map<String, Object> manifest(ReportInput input, Path root, List<Path> files) throws IOException {
        List<Map<String, Object>> fileEntries = new ArrayList<>();
        for (Path file : files) {
            fileEntries.add(orderedMap("path", portable(root.relativize(file)), "size", Files.size(file),
                    "sha256", sha256(Files.readAllBytes(file))));
        }
        return orderedMap(
                "schemaVersion", 1, "scanId", input.scanId().toString(), "profile", input.profile().name(),
                "createdAt", input.createdAt().toString(), "completedAt", input.completedAt().toString(),
                "source", input.source(),
                "runtime", orderedMap("javaVersion", System.getProperty("java.version"),
                        "mavenVersion", input.toolchain().getOrDefault("mavenVersion", "unknown"),
                        "os", System.getProperty("os.name"), "architecture", System.getProperty("os.arch")),
                "maven", input.build(), "tools", listValue(input.toolchain().get("tools")),
                "rules", listValue(input.toolchain().get("rules")),
                "databases", listValue(input.toolchain().get("databases")),
                "configFingerprint", input.configFingerprint(),
                "report", Map.of("schemaVersion", "1.0", "fingerprintVersion", 1, "parserSchemaVersion", 1),
                "files", fileEntries);
    }

    @SuppressWarnings("unchecked")
    private void validateManifestHashes(Path root, Map<String, Object> manifest) throws IOException {
        for (Map<String, Object> entry : (List<Map<String, Object>>) manifest.get("files")) {
            Path file = root.resolve(String.valueOf(entry.get("path"))).normalize();
            if (!file.startsWith(root) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                    || Files.size(file) != ((Number) entry.get("size")).longValue()
                    || !sha256(Files.readAllBytes(file)).equals(entry.get("sha256"))) {
                throw new IOException("manifest file integrity check failed: " + entry.get("path"));
            }
        }
    }

    private void validateArchive(Path archive) throws IOException {
        try (ZipFile zip = new ZipFile(archive.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (name.startsWith("/") || name.contains("../") || name.equals("..")
                        || forbiddenReportArtifact(name)) {
                    throw new IOException("unsafe or forbidden report archive entry: " + name);
                }
            }
        }
    }

    private boolean forbiddenReportArtifact(String portablePath) {
        return portablePath.startsWith("source/")
                || portablePath.startsWith("workspace/")
                || portablePath.startsWith("build/")
                || portablePath.startsWith("codeql-db/")
                || portablePath.startsWith("raw/codeql/database/")
                || portablePath.equals("raw/codeql/database")
                || portablePath.contains("/target/");
    }

    private Path verifiedJobRoot(Path jobRoot) throws IOException {
        Objects.requireNonNull(jobRoot, "jobRoot");
        Path root = jobRoot.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(root)) {
            throw new IOException("job root must not be a symbolic link");
        }
        Files.createDirectories(root);
        return root;
    }

    private void ensureImmutableTargetsAbsent(List<Path> targets) throws IOException {
        for (Path target : targets) {
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("final report revision is immutable and already exists: " + target);
            }
        }
    }

    private Map<String, Object> artifact(String path, String type) {
        return Map.of("path", path, "type", type);
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
        return first != null && !first.isBlank() ? first : second == null ? "" : second;
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

    private String portable(Path path) {
        return path.toString().replace(path.getFileSystem().getSeparator(), "/");
    }

    private String escape(Object value) {
        String text = String.valueOf(value);
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static ObjectMapper defaultMapper() {
        return new ObjectMapper().registerModule(new JavaTimeModule())
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
