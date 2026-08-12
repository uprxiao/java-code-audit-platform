package io.github.uprxiao.audit.adapter.semgrep;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.finding.CodeSnippet;
import io.github.uprxiao.audit.finding.Confidence;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingEvidence;
import io.github.uprxiao.audit.finding.FindingFingerprintService;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ReviewState;
import io.github.uprxiao.audit.finding.Severity;
import io.github.uprxiao.audit.finding.SeverityMappingRequest;
import io.github.uprxiao.audit.finding.SeverityMappingResult;
import io.github.uprxiao.audit.finding.SeverityMappingService;
import io.github.uprxiao.audit.finding.SourceLocation;
import io.github.uprxiao.audit.finding.VulnerabilityIdentifiers;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.scanner.Applicability;
import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.EngineDescriptor;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.ExpectedArtifact;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ScannerAdapter;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.IOException;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class SemgrepAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("semgrep");
    private static final long MAX_REPORT_BYTES = 256L * 1024 * 1024;

    private final Path rulesFile;
    private final ObjectMapper json;
    private final FindingFingerprintService fingerprints = new FindingFingerprintService();
    private final SeverityMappingService severities = new SeverityMappingService();

    public SemgrepAdapter(Path rulesFile) {
        this(rulesFile, new ObjectMapper());
    }

    SemgrepAdapter(Path rulesFile, ObjectMapper json) {
        this.rulesFile = Objects.requireNonNull(rulesFile, "rulesFile").toAbsolutePath().normalize();
        this.json = Objects.requireNonNull(json, "json");
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "Semgrep CE", false,
                new ResourceRequest(ResourceClass.MEDIUM, 2, 2048), Duration.ofMinutes(15), Set.of());
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_UNAVAILABLE", "Semgrep executable is unavailable");
        }
        if (!Files.isRegularFile(rulesFile)) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "RULES_UNAVAILABLE", rulesFile.toString());
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            throw new IOException("Semgrep tool installation is unavailable");
        }
        Files.createDirectories(context.engineOutputDirectory());
        Path isolatedHome = Files.createDirectories(context.engineOutputDirectory().resolve("home"));
        Path isolatedTemp = Files.createDirectories(context.engineOutputDirectory().resolve("tmp"));
        Path report = context.engineOutputDirectory().resolve("report.json");
        List<String> command = List.of(
                installation.executable().toString(),
                "scan",
                "--config", rulesFile.toString(),
                "--json",
                "--output", report.toString(),
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                "--no-rewrite-rule-ids",
                "--jobs=2",
                context.project().workspaceRoot().toString());
        String safePath = installation.executable().getParent() + File.pathSeparator + "/usr/bin" + File.pathSeparator + "/bin";
        Map<String, String> environment = Map.of(
                "PATH", safePath,
                "HOME", isolatedHome.toString(),
                "TMPDIR", isolatedTemp.toString(),
                "PYTHONDONTWRITEBYTECODE", "1");
        return new ExecutionSpec(ID, command, context.engineOutputDirectory(), environment, descriptor().defaultTimeout(),
                descriptor().resources(), Set.of(new ExpectedArtifact("report.json", true, MAX_REPORT_BYTES)),
                RedactionPolicy.NONE);
    }

    @Override
    public ArtifactValidation validate(RawArtifactSet artifacts) throws IOException {
        List<String> errors = new ArrayList<>();
        if (!ID.equals(artifacts.engine())) {
            errors.add("ENGINE_MISMATCH");
        }
        if (artifacts.execution().status() != ExecutionResult.Status.SUCCEEDED) {
            errors.add("EXECUTION_" + artifacts.execution().status());
        }
        Path report = artifacts.artifacts().get("report");
        if (report == null || !Files.isRegularFile(report)) {
            errors.add("REPORT_MISSING");
        } else if (Files.size(report) > MAX_REPORT_BYTES) {
            errors.add("REPORT_TOO_LARGE");
        } else {
            try {
                JsonNode root = json.readTree(report.toFile());
                if (root == null || !root.path("results").isArray() || !root.path("errors").isArray()) {
                    errors.add("REPORT_SCHEMA_INVALID");
                }
            } catch (IOException exception) {
                errors.add("REPORT_JSON_INVALID");
            }
        }
        return new ArtifactValidation(errors.isEmpty(), errors);
    }

    @Override
    public NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) throws IOException {
        ArtifactValidation validation = validate(artifacts);
        if (!validation.valid()) {
            throw new IOException("Semgrep artifacts are invalid: " + validation.errors());
        }
        Path reportPath = artifacts.artifacts().get("report");
        JsonNode report = json.readTree(reportPath.toFile());
        String version = report.path("version").asText("unknown");
        List<Finding> findings = new ArrayList<>();
        int index = 0;
        for (JsonNode result : report.path("results")) {
            findings.add(toFinding(context.project(), result, version, index++));
        }
        List<String> warnings = new ArrayList<>();
        for (JsonNode error : report.path("errors")) {
            warnings.add(error.path("message").asText(error.toString()));
        }
        int moduleCount = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        EngineCoverage coverage = new EngineCoverage(
                ID.value(), status, moduleCount, moduleCount, moduleCount, findings.size(),
                artifacts.execution().duration(), warnings.isEmpty() ? "" : "SEMGREP_PARTIAL_ERRORS",
                "raw/semgrep/report.json");
        return new NormalizationResult(findings, coverage, warnings);
    }

    private Finding toFinding(ProjectContext project, JsonNode result, String version, int index) throws IOException {
        String ruleId = requiredText(result, "check_id");
        JsonNode extra = result.path("extra");
        JsonNode metadata = extra.path("metadata");
        Path relativePath = normalizePath(project, requiredText(result, "path"));
        int startLine = result.path("start").path("line").asInt();
        int startColumn = result.path("start").path("col").asInt();
        int endLine = result.path("end").path("line").asInt();
        int endColumn = result.path("end").path("col").asInt();
        String message = extra.path("message").asText(ruleId);
        String ruleFamily = metadata.path("rule_family").asText(ruleId).toUpperCase(Locale.ROOT);
        SourceLocation location = new SourceLocation(portable(relativePath), startLine, startColumn, endLine, endColumn);
        CodeSnippet snippet = snippet(project.resolveProjectPath(portable(relativePath)), startLine, endLine);
        IssueCategory category = enumValue(
                IssueCategory.class, metadata.path("audit_category").asText(), IssueCategory.CORRECTNESS);
        Confidence confidence = enumValue(
                Confidence.class, metadata.path("confidence").asText(), Confidence.MEDIUM);
        FindingFingerprintService.Fingerprint fingerprint = fingerprints.source(
                ruleFamily, portable(relativePath), ruleId, "", message, snippet.text());
        SeverityMappingResult severity = severities.map(new SeverityMappingRequest(
                ID.value(), ruleFamily, category, extra.path("severity").asText(),
                null, false, false, confidence));
        Map<String, Object> properties = new java.util.LinkedHashMap<>(
                json.convertValue(metadata, new TypeReference<Map<String, Object>>() { }));
        properties.put("severityMappingId", severity.mappingId());
        properties.put("severityMappingReason", severity.reason());
        FindingEvidence evidence = new FindingEvidence(
                ID.value(), version, ruleId, extra.path("severity").asText(""),
                "raw/semgrep/report.json", ruleId + ":" + index,
                properties);
        return new Finding(
                fingerprint.findingId(),
                fingerprint.value(),
                fingerprint.version(),
                category,
                severity.severity(),
                confidence,
                ruleFamily,
                metadata.path("title_zh").asText(""),
                message,
                metadata.path("description_zh").asText(""),
                message,
                metadata.path("impact_zh").asText(""),
                metadata.path("remediation_zh").asText(""),
                moduleFor(project, relativePath),
                location,
                snippet,
                new VulnerabilityIdentifiers(stringList(metadata.path("cwe")), List.of(), List.of(), List.of()),
                null,
                List.of(),
                List.of(evidence),
                null,
                ReviewState.UNREVIEWED);
    }

    private Path normalizePath(ProjectContext project, String rawPath) throws IOException {
        Path path = Path.of(rawPath);
        Path absolute = path.isAbsolute()
                ? path.normalize()
                : project.workspaceRoot().resolve(path).normalize();
        if (!absolute.startsWith(project.workspaceRoot())) {
            throw new IOException("Semgrep finding path escapes project root: " + rawPath);
        }
        return project.workspaceRoot().relativize(absolute);
    }

    private CodeSnippet snippet(Path source, int startLine, int endLine) throws IOException {
        List<String> lines = Files.readAllLines(source, StandardCharsets.UTF_8);
        int snippetStart = Math.max(1, startLine - 5);
        int snippetEnd = Math.min(lines.size(), Math.max(endLine, startLine) + 5);
        List<String> selected = lines.subList(snippetStart - 1, snippetEnd);
        List<Integer> highlights = java.util.stream.IntStream.rangeClosed(startLine, Math.min(endLine, snippetEnd))
                .boxed().toList();
        return new CodeSnippet(snippetStart, snippetEnd, highlights, String.join("\n", selected), false);
    }

    private String moduleFor(ProjectContext project, Path relativePath) {
        return project.manifest().modules().stream()
                .filter(module -> !module.path().equals("."))
                .filter(module -> relativePath.startsWith(Path.of(module.path())))
                .map(module -> module.artifactId())
                .findFirst()
                .orElse(project.manifest().modules().isEmpty() ? "" : project.manifest().modules().get(0).artifactId());
    }

    private Severity severity(String semgrepSeverity) {
        return switch (semgrepSeverity.toUpperCase(Locale.ROOT)) {
            case "ERROR", "CRITICAL", "HIGH" -> Severity.P1;
            case "WARNING", "MEDIUM" -> Severity.P2;
            default -> Severity.P3;
        };
    }

    private <E extends Enum<E>> E enumValue(Class<E> type, String value, E fallback) {
        try {
            return Enum.valueOf(type, value.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            return fallback;
        }
    }

    private List<String> stringList(JsonNode node) {
        if (node.isArray()) {
            List<String> values = new ArrayList<>();
            node.forEach(value -> values.add(value.asText()));
            return List.copyOf(values);
        }
        return node.isTextual() ? List.of(node.asText()) : List.of();
    }

    private String requiredText(JsonNode node, String field) throws IOException {
        String value = node.path(field).asText();
        if (value.isBlank()) {
            throw new IOException("Semgrep result is missing field: " + field);
        }
        return value;
    }

    private String normalizedMessage(String value) {
        return value.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim();
    }

    private String fingerprint(String canonical) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    private String portable(Path path) {
        return path.toString().replace(path.getFileSystem().getSeparator(), "/");
    }
}
