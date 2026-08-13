package io.github.uprxiao.audit.adapter.trivy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.adapter.support.AdapterSupport;
import io.github.uprxiao.audit.finding.CodeSnippet;
import io.github.uprxiao.audit.finding.Confidence;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingEvidence;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ReviewState;
import io.github.uprxiao.audit.finding.Severity;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class TrivyRepositoryAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("trivy-repository");
    public static final String TOOL_VERSION = "0.73.0";
    private static final long MAX_REPORT_BYTES = 512L * 1024 * 1024;

    private final Path cacheDirectory;
    private final ObjectMapper json;

    public TrivyRepositoryAdapter(Path cacheDirectory) {
        this(cacheDirectory, new ObjectMapper());
    }

    TrivyRepositoryAdapter(Path cacheDirectory, ObjectMapper json) {
        this.cacheDirectory = Objects.requireNonNull(cacheDirectory).toAbsolutePath().normalize();
        this.json = Objects.requireNonNull(json);
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "Trivy Repository", false,
                new ResourceRequest(ResourceClass.MEDIUM, 2, 2048), Duration.ofMinutes(20), Set.of());
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_UNAVAILABLE", "Trivy executable is unavailable");
        }
        if (!TOOL_VERSION.equals(installation.version())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_VERSION_MISMATCH", installation.version());
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, ID);
        Files.createDirectories(context.engineOutputDirectory());
        Files.createDirectories(cacheDirectory);
        Path report = context.engineOutputDirectory().resolve("report.json");
        List<String> command = List.of(
                installation.executable().toString(), "repo",
                "--scanners", "misconfig,secret,license", "--format", "json", "--output", report.toString(),
                "--cache-dir", cacheDirectory.toString(), "--offline-scan", "--quiet", "--no-progress", "--parallel", "2",
                "--timeout", "15m", "--exit-code", "0", context.project().workspaceRoot().toString());
        return new ExecutionSpec(ID, command, context.engineOutputDirectory(),
                AdapterSupport.isolatedEnvironment(context.engineOutputDirectory(), installation.executable()),
                descriptor().defaultTimeout(), descriptor().resources(),
                Set.of(new ExpectedArtifact("report.json", true, MAX_REPORT_BYTES)), RedactionPolicy.NONE);
    }

    @Override
    public ArtifactValidation validate(RawArtifactSet artifacts) throws IOException {
        List<String> errors = new ArrayList<>();
        if (!ID.equals(artifacts.engine())) errors.add("ENGINE_MISMATCH");
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
                if (root == null || !root.path("Results").isArray()) {
                    errors.add("REPORT_SCHEMA_INVALID");
                } else if (!secretsAreRedacted(root)) {
                    errors.add("REPORT_CONTAINS_UNREDACTED_SECRET");
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
        if (!validation.valid()) throw new IOException("Trivy artifacts are invalid: " + validation.errors());
        JsonNode root = json.readTree(artifacts.artifacts().get("report").toFile());
        List<Finding> findings = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        root.path("Errors").forEach(error -> warnings.add("TRIVY_ERROR: " + error.toString()));
        int index = 0;
        for (JsonNode result : root.path("Results")) {
            result.path("Errors").forEach(error -> warnings.add("TRIVY_RESULT_ERROR: " + error.toString()));
            String target = result.path("Target").asText();
            for (JsonNode misconfiguration : result.path("Misconfigurations")) {
                try {
                    findings.add(misconfiguration(context.project(), target, misconfiguration, index));
                } catch (IOException | IllegalArgumentException exception) {
                    warnings.add("TRIVY_MISCONFIG_" + index + ": " + exception.getMessage());
                }
                index++;
            }
            for (JsonNode secret : result.path("Secrets")) {
                try {
                    findings.add(secret(context.project(), target, secret, index));
                } catch (IOException | IllegalArgumentException exception) {
                    warnings.add("TRIVY_SECRET_" + index + ": " + exception.getMessage());
                }
                index++;
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(findings,
                new EngineCoverage(ID.value(), status, modules, modules, modules, findings.size(),
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "TRIVY_PARTIAL_ERRORS",
                        "raw/trivy-repository/report.json"), warnings);
    }

    private Finding misconfiguration(ProjectContext project, String target, JsonNode item, int index) throws IOException {
        String ruleId = required(item, "ID");
        Path relative = AdapterSupport.normalizeFindingPath(project, target);
        JsonNode cause = item.path("CauseMetadata");
        int startLine = Math.max(1, cause.path("StartLine").asInt(1));
        int endLine = Math.max(startLine, cause.path("EndLine").asInt(startLine));
        boolean locationAvailable = cause.path("StartLine").asInt() > 0;
        String title = item.path("Title").asText(ruleId);
        String message = item.path("Message").asText(title);
        String fingerprint = AdapterSupport.fingerprint("TRIVY_MISCONFIG|" + ruleId + "|"
                + AdapterSupport.portable(relative) + "|" + AdapterSupport.normalizedMessage(message));
        FindingEvidence evidence = new FindingEvidence(ID.value(), TOOL_VERSION, ruleId,
                item.path("Severity").asText("UNKNOWN"), "raw/trivy-repository/report.json", ruleId + ":" + index,
                Map.of("namespace", item.path("Namespace").asText(""), "primaryUrl", item.path("PrimaryURL").asText(""),
                        "locationAvailable", locationAvailable));
        CodeSnippet snippet = locationAvailable ? AdapterSupport.snippet(project, relative, startLine, endLine) : null;
        return new Finding(AdapterSupport.findingId(fingerprint), fingerprint, 1, IssueCategory.CONFIG_IAC_SECURITY,
                severity(item.path("Severity").asText()), Confidence.HIGH, ruleId, "仓库配置安全：" + title, title,
                item.path("Description").asText(""), message, "错误配置可能扩大部署或运行环境的攻击面。",
                item.path("Resolution").asText("按规则说明修正配置并复核实际部署环境。"),
                AdapterSupport.moduleFor(project, relative),
                new SourceLocation(AdapterSupport.portable(relative), startLine, 0, endLine, 0), snippet,
                VulnerabilityIdentifiers.EMPTY, null, List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    private Finding secret(ProjectContext project, String target, JsonNode item, int index) throws IOException {
        String ruleId = required(item, "RuleID");
        Path relative = AdapterSupport.normalizeFindingPath(project, target);
        int startLine = positive(item.path("StartLine").asInt(), "StartLine");
        int endLine = Math.max(startLine, item.path("EndLine").asInt(startLine));
        String title = item.path("Title").asText(ruleId);
        String fingerprint = AdapterSupport.fingerprint("TRIVY_SECRET|" + ruleId + "|"
                + AdapterSupport.portable(relative) + "|" + startLine);
        FindingEvidence evidence = new FindingEvidence(ID.value(), TOOL_VERSION, ruleId,
                item.path("Severity").asText("UNKNOWN"), "raw/trivy-repository/report.json", ruleId + ":" + index,
                Map.of("category", item.path("Category").asText(""), "redacted", true));
        return new Finding(AdapterSupport.findingId(fingerprint), fingerprint, 1, IssueCategory.SECRET_EXPOSURE,
                severity(item.path("Severity").asText()), Confidence.HIGH, "HARDCODED_SECRET",
                "仓库中疑似包含密钥或凭据", title, "Trivy 在当前仓库快照中识别到敏感凭据模式。", title,
                "泄漏的凭据可能被用于未授权访问。", "立即撤销或轮换凭据，并改用受控密钥存储。",
                AdapterSupport.moduleFor(project, relative),
                new SourceLocation(AdapterSupport.portable(relative), startLine, 0, endLine, 0),
                AdapterSupport.redactedSnippet(startLine, endLine, "secret"),
                new VulnerabilityIdentifiers(List.of("CWE-798"), List.of(), List.of(), List.of()),
                null, List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    private boolean secretsAreRedacted(JsonNode root) {
        for (JsonNode result : root.path("Results")) {
            for (JsonNode secret : result.path("Secrets")) {
                String match = secret.path("Match").asText();
                if (!match.isBlank() && !match.contains("***")) return false;
                for (JsonNode line : secret.path("Code").path("Lines")) {
                    if (line.path("IsCause").asBoolean() && !line.path("Content").asText().contains("***")) return false;
                }
            }
        }
        return true;
    }

    private Severity severity(String value) {
        return switch (value.toUpperCase(Locale.ROOT)) {
            case "CRITICAL", "HIGH" -> Severity.P1;
            case "MEDIUM" -> Severity.P2;
            default -> Severity.P3;
        };
    }

    private String required(JsonNode node, String field) throws IOException {
        String value = node.path(field).asText();
        if (value.isBlank()) throw new IOException("missing field " + field);
        return value;
    }

    private int positive(int value, String field) throws IOException {
        if (value < 1) throw new IOException("invalid " + field);
        return value;
    }
}
