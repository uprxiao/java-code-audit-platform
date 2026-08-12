package io.github.uprxiao.audit.adapter.gitleaks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.adapter.support.AdapterSupport;
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
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class GitleaksAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("gitleaks");
    public static final String TOOL_VERSION = "8.30.1";
    private static final long MAX_REPORT_BYTES = 128L * 1024 * 1024;

    private final Path configurationFile;
    private final ObjectMapper json;

    public GitleaksAdapter(Path configurationFile) {
        this(configurationFile, new ObjectMapper());
    }

    GitleaksAdapter(Path configurationFile, ObjectMapper json) {
        this.configurationFile = Objects.requireNonNull(configurationFile).toAbsolutePath().normalize();
        this.json = Objects.requireNonNull(json);
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "Gitleaks", false,
                new ResourceRequest(ResourceClass.LIGHT, 1, 512), Duration.ofMinutes(10), Set.of());
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_UNAVAILABLE", "Gitleaks executable is unavailable");
        }
        if (!TOOL_VERSION.equals(installation.version())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_VERSION_MISMATCH", installation.version());
        }
        if (!Files.isRegularFile(configurationFile)) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "RULES_UNAVAILABLE", configurationFile.toString());
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, ID);
        Files.createDirectories(context.engineOutputDirectory());
        Path report = context.engineOutputDirectory().resolve("report.json");
        List<String> command = List.of(
                installation.executable().toString(), "dir",
                "--no-banner", "--no-color", "--redact=100",
                "--config", configurationFile.toString(),
                "--report-format", "json", "--report-path", report.toString(),
                "--exit-code", "0", context.project().workspaceRoot().toString());
        return new ExecutionSpec(ID, command, context.engineOutputDirectory(),
                AdapterSupport.isolatedEnvironment(context.engineOutputDirectory(), installation.executable()),
                descriptor().defaultTimeout(), descriptor().resources(),
                Set.of(new ExpectedArtifact("report.json", true, MAX_REPORT_BYTES)), RedactionPolicy.NONE);
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
                if (root == null || !root.isArray()) {
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
        if (!validation.valid()) {
            throw new IOException("Gitleaks artifacts are invalid: " + validation.errors());
        }
        JsonNode report = json.readTree(artifacts.artifacts().get("report").toFile());
        List<Finding> findings = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        int index = 0;
        for (JsonNode leak : report) {
            try {
                findings.add(toFinding(context.project(), leak, index));
            } catch (IOException | IllegalArgumentException exception) {
                warnings.add("GITLEAKS_ITEM_" + index + ": " + exception.getMessage());
            }
            index++;
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(findings,
                new EngineCoverage(ID.value(), status, modules, modules, modules, findings.size(),
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "GITLEAKS_PARTIAL_PARSE",
                        "raw/gitleaks/report.json"), warnings);
    }

    private Finding toFinding(ProjectContext project, JsonNode leak, int index) throws IOException {
        String ruleId = required(leak, "RuleID");
        Path relative = AdapterSupport.normalizeFindingPath(project, required(leak, "File"));
        int startLine = positive(leak.path("StartLine").asInt(), "StartLine");
        int endLine = Math.max(startLine, leak.path("EndLine").asInt(startLine));
        int startColumn = Math.max(0, leak.path("StartColumn").asInt());
        int endColumn = Math.max(startColumn, leak.path("EndColumn").asInt(startColumn));
        String description = leak.path("Description").asText(ruleId);
        String canonical = ruleId + "|" + AdapterSupport.portable(relative) + "|" + startLine + "|"
                + AdapterSupport.normalizedMessage(description);
        String fingerprint = AdapterSupport.fingerprint(canonical);
        List<String> tags = new ArrayList<>();
        leak.path("Tags").forEach(tag -> tags.add(tag.asText()));
        Map<String, Object> properties = Map.of(
                "redacted", true,
                "entropy", leak.path("Entropy").asDouble(0),
                "tags", List.copyOf(tags));
        FindingEvidence evidence = new FindingEvidence(ID.value(), TOOL_VERSION, ruleId, "HIGH",
                "raw/gitleaks/report.json", ruleId + ":" + index, properties);
        return new Finding(AdapterSupport.findingId(fingerprint), fingerprint, 1,
                IssueCategory.SECRET_EXPOSURE, Severity.P1, Confidence.HIGH, "HARDCODED_SECRET",
                "源码中疑似包含密钥或凭据", description, "扫描器在当前源码快照中识别到敏感凭据模式。",
                description, "泄漏的凭据可能被用于未授权访问。", "立即撤销或轮换凭据，并改用受控密钥存储。",
                AdapterSupport.moduleFor(project, relative),
                new SourceLocation(AdapterSupport.portable(relative), startLine, startColumn, endLine, endColumn),
                AdapterSupport.redactedSnippet(startLine, endLine, "secret"),
                new VulnerabilityIdentifiers(List.of("CWE-798"), List.of(), List.of(), List.of()),
                null, List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    private String required(JsonNode node, String field) throws IOException {
        String value = node.path(field).asText();
        if (value.isBlank()) {
            throw new IOException("missing field " + field);
        }
        return value;
    }

    private int positive(int value, String field) throws IOException {
        if (value < 1) {
            throw new IOException("invalid " + field);
        }
        return value;
    }

    private boolean secretsAreRedacted(JsonNode root) {
        for (JsonNode leak : root) {
            String secret = leak.path("Secret").asText();
            if (!secret.isBlank() && !secret.contains("***") && !secret.toUpperCase(java.util.Locale.ROOT).contains("REDACTED")) {
                return false;
            }
            String match = leak.path("Match").asText();
            if (!match.isBlank() && !match.contains("***") && !match.toUpperCase(java.util.Locale.ROOT).contains("REDACTED")) {
                return false;
            }
        }
        return true;
    }
}
