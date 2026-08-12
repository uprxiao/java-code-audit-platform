package io.github.uprxiao.audit.adapter.pmd;

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
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class PmdAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("pmd");
    public static final String TOOL_VERSION = "7.26.0";
    private static final long MAX_REPORT_BYTES = 256L * 1024 * 1024;

    private final Path rulesFile;
    private final Path pmdHome;
    private final ObjectMapper json;

    public PmdAdapter(Path rulesFile, Path pmdHome) {
        this(rulesFile, pmdHome, new ObjectMapper());
    }

    PmdAdapter(Path rulesFile, Path pmdHome, ObjectMapper json) {
        this.rulesFile = Objects.requireNonNull(rulesFile).toAbsolutePath().normalize();
        this.pmdHome = Objects.requireNonNull(pmdHome).toAbsolutePath().normalize();
        this.json = Objects.requireNonNull(json);
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "PMD", false,
                new ResourceRequest(ResourceClass.MEDIUM, 2, 1536), Duration.ofMinutes(15), Set.of());
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_UNAVAILABLE", "PMD Java launcher is unavailable");
        }
        if (!TOOL_VERSION.equals(installation.version())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_VERSION_MISMATCH", installation.version());
        }
        if (!Files.isRegularFile(rulesFile)) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "RULES_UNAVAILABLE", rulesFile.toString());
        }
        if (!Files.isDirectory(pmdHome.resolve("lib"))) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "PMD_HOME_INVALID", pmdHome.toString());
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, ID);
        Files.createDirectories(context.engineOutputDirectory());
        Path report = context.engineOutputDirectory().resolve("report.json");
        List<String> command = List.of(
                installation.executable().toString(), "-cp", pmdHome.resolve("lib/*").toString(),
                "net.sourceforge.pmd.cli.PmdCli", "check",
                "--dir", context.project().workspaceRoot().toString(),
                "--rulesets", rulesFile.toString(), "--use-version", "java-17",
                "--format", "json", "--report-file", report.toString(),
                "--relativize-paths-with", context.project().workspaceRoot().toString(),
                "--no-cache", "--no-progress", "--no-fail-on-violation", "--no-fail-on-error", "--threads", "2");
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
                if (root == null || !root.path("files").isArray()
                        || !root.path("processingErrors").isArray() || !root.path("configurationErrors").isArray()) {
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
            throw new IOException("PMD artifacts are invalid: " + validation.errors());
        }
        JsonNode root = json.readTree(artifacts.artifacts().get("report").toFile());
        String version = root.path("pmdVersion").asText(TOOL_VERSION);
        List<Finding> findings = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        root.path("processingErrors").forEach(error -> warnings.add("PMD_PROCESSING_ERROR: " + error.toString()));
        root.path("configurationErrors").forEach(error -> warnings.add("PMD_CONFIGURATION_ERROR: " + error.toString()));
        int index = 0;
        for (JsonNode file : root.path("files")) {
            for (JsonNode violation : file.path("violations")) {
                try {
                    findings.add(toFinding(context.project(), file.path("filename").asText(), violation, version, index));
                } catch (IOException | IllegalArgumentException exception) {
                    warnings.add("PMD_ITEM_" + index + ": " + exception.getMessage());
                }
                index++;
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(findings,
                new EngineCoverage(ID.value(), status, modules, modules, modules, findings.size(),
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "PMD_PARTIAL_ERRORS",
                        "raw/pmd/report.json"), warnings);
    }

    private Finding toFinding(ProjectContext project, String filename, JsonNode violation, String version, int index)
            throws IOException {
        String rule = required(violation, "rule");
        String ruleset = violation.path("ruleset").asText("");
        String description = violation.path("description").asText(rule);
        Path relative = AdapterSupport.normalizeFindingPath(project, filename);
        int startLine = positive(violation.path("beginline").asInt(), "beginline");
        int endLine = Math.max(startLine, violation.path("endline").asInt(startLine));
        int startColumn = Math.max(0, violation.path("begincolumn").asInt());
        int endColumn = Math.max(startColumn, violation.path("endcolumn").asInt(startColumn));
        String ruleFamily = rule.replaceAll("([a-z])([A-Z])", "$1_$2").toUpperCase(Locale.ROOT);
        String fingerprint = AdapterSupport.fingerprint(ruleFamily + "|" + AdapterSupport.portable(relative) + "|"
                + AdapterSupport.normalizedMessage(description));
        int priority = violation.path("priority").asInt(3);
        FindingEvidence evidence = new FindingEvidence(ID.value(), version, rule, Integer.toString(priority),
                "raw/pmd/report.json", rule + ":" + index,
                Map.of("ruleset", ruleset, "priority", priority,
                        "externalInfoUrl", violation.path("externalInfoUrl").asText("")));
        IssueCategory category = category(rule, ruleset);
        return new Finding(AdapterSupport.findingId(fingerprint), fingerprint, 1, category, severity(priority),
                Confidence.MEDIUM, ruleFamily, "PMD：" + rule, rule, "PMD 源码规则识别到潜在问题。",
                description, impact(category), remediation(category), AdapterSupport.moduleFor(project, relative),
                new SourceLocation(AdapterSupport.portable(relative), startLine, startColumn, endLine, endColumn),
                AdapterSupport.snippet(project, relative, startLine, endLine), VulnerabilityIdentifiers.EMPTY,
                null, List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    private IssueCategory category(String rule, String ruleset) {
        String value = (rule + " " + ruleset).toLowerCase(Locale.ROOT);
        if (value.matches(".*(thread|lock|synchron|concurr).*")) return IssueCategory.CONCURRENCY;
        if (value.matches(".*(close|resource|performance|stream).*")) return IssueCategory.RESOURCE_PERFORMANCE;
        if (value.contains("code style")) return IssueCategory.CODE_STYLE;
        if (value.contains("design")) return IssueCategory.MAINTAINABILITY;
        return IssueCategory.CORRECTNESS;
    }

    private Severity severity(int priority) {
        return switch (priority) {
            case 1 -> Severity.P1;
            case 2, 3 -> Severity.P2;
            default -> Severity.P3;
        };
    }

    private String impact(IssueCategory category) {
        return category == IssueCategory.RESOURCE_PERFORMANCE ? "可能造成资源泄漏或不必要的性能开销。" : "可能影响代码正确性或长期维护成本。";
    }

    private String remediation(IssueCategory category) {
        return category == IssueCategory.RESOURCE_PERFORMANCE ? "按规则建议关闭资源并采用更合适的 API。" : "复核规则证据并按项目约定重构。";
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
