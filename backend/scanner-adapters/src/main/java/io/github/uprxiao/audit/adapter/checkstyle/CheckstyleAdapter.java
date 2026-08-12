package io.github.uprxiao.audit.adapter.checkstyle;

import io.github.uprxiao.audit.adapter.support.AdapterSupport;
import io.github.uprxiao.audit.adapter.support.SecureXml;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public final class CheckstyleAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("checkstyle");
    public static final String TOOL_VERSION = "12.3.1";
    private static final long MAX_REPORT_BYTES = 256L * 1024 * 1024;

    private final Path configurationFile;
    private final Path checkstyleJar;

    public CheckstyleAdapter(Path configurationFile, Path checkstyleJar) {
        this.configurationFile = Objects.requireNonNull(configurationFile).toAbsolutePath().normalize();
        this.checkstyleJar = Objects.requireNonNull(checkstyleJar).toAbsolutePath().normalize();
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "Checkstyle", false,
                new ResourceRequest(ResourceClass.LIGHT, 1, 1024), Duration.ofMinutes(10), Set.of());
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_UNAVAILABLE", "Java launcher is unavailable");
        }
        if (!TOOL_VERSION.equals(installation.version())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_VERSION_MISMATCH", installation.version());
        }
        if (!Files.isRegularFile(configurationFile)) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "RULES_UNAVAILABLE", configurationFile.toString());
        }
        if (!Files.isRegularFile(checkstyleJar)) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "CHECKSTYLE_JAR_INVALID", checkstyleJar.toString());
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, ID);
        Files.createDirectories(context.engineOutputDirectory());
        Path report = context.engineOutputDirectory().resolve("report.xml");
        List<String> command = List.of(
                installation.executable().toString(), "-Duser.language=en", "-Duser.country=US",
                "-jar", checkstyleJar.toString(), "-c", configurationFile.toString(),
                "-f", "xml", "-o", report.toString(), context.project().workspaceRoot().toString());
        return new ExecutionSpec(ID, command, context.engineOutputDirectory(),
                AdapterSupport.isolatedEnvironment(context.engineOutputDirectory(), installation.executable()),
                descriptor().defaultTimeout(), descriptor().resources(),
                Set.of(new ExpectedArtifact("report.xml", true, MAX_REPORT_BYTES)), RedactionPolicy.NONE);
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
                Document document = SecureXml.parse(report);
                if (!"checkstyle".equals(document.getDocumentElement().getNodeName())) errors.add("REPORT_SCHEMA_INVALID");
            } catch (IOException exception) {
                errors.add("REPORT_XML_INVALID");
            }
        }
        return new ArtifactValidation(errors.isEmpty(), errors);
    }

    @Override
    public NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) throws IOException {
        ArtifactValidation validation = validate(artifacts);
        if (!validation.valid()) throw new IOException("Checkstyle artifacts are invalid: " + validation.errors());
        Document document = SecureXml.parse(artifacts.artifacts().get("report"));
        String version = document.getDocumentElement().getAttribute("version");
        if (version.isBlank()) version = TOOL_VERSION;
        List<Finding> findings = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        NodeList files = document.getElementsByTagName("file");
        int index = 0;
        for (int fileIndex = 0; fileIndex < files.getLength(); fileIndex++) {
            Element file = (Element) files.item(fileIndex);
            NodeList exceptions = file.getElementsByTagName("exception");
            for (int errorIndex = 0; errorIndex < exceptions.getLength(); errorIndex++) {
                warnings.add("CHECKSTYLE_PROCESSING_ERROR: " + exceptions.item(errorIndex).getTextContent());
            }
            NodeList errors = file.getElementsByTagName("error");
            for (int errorIndex = 0; errorIndex < errors.getLength(); errorIndex++) {
                try {
                    findings.add(toFinding(context.project(), file.getAttribute("name"),
                            (Element) errors.item(errorIndex), version, index));
                } catch (IOException | IllegalArgumentException exception) {
                    warnings.add("CHECKSTYLE_ITEM_" + index + ": " + exception.getMessage());
                }
                index++;
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(findings,
                new EngineCoverage(ID.value(), status, modules, modules, modules, findings.size(),
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "CHECKSTYLE_PARTIAL_ERRORS",
                        "raw/checkstyle/report.xml"), warnings);
    }

    private Finding toFinding(ProjectContext project, String filename, Element error, String version, int index)
            throws IOException {
        Path relative = AdapterSupport.normalizeFindingPath(project, filename);
        int line = positive(error.getAttribute("line"), "line");
        int column = nonNegative(error.getAttribute("column"));
        String source = required(error.getAttribute("source"), "source");
        String rule = source.substring(source.lastIndexOf('.') + 1).replaceFirst("Check$", "");
        String message = required(error.getAttribute("message"), "message");
        String engineSeverity = error.getAttribute("severity");
        String ruleFamily = rule.replaceAll("([a-z])([A-Z])", "$1_$2").toUpperCase(Locale.ROOT);
        String fingerprint = AdapterSupport.fingerprint(ruleFamily + "|" + AdapterSupport.portable(relative) + "|"
                + AdapterSupport.normalizedMessage(message));
        FindingEvidence evidence = new FindingEvidence(ID.value(), version, source, engineSeverity,
                "raw/checkstyle/report.xml", source + ":" + index, Map.of("checker", source));
        return new Finding(AdapterSupport.findingId(fingerprint), fingerprint, 1, IssueCategory.CODE_STYLE,
                severity(engineSeverity), Confidence.HIGH, ruleFamily, "Checkstyle：" + rule, rule,
                "代码不符合当前仓库锁定的 Checkstyle 规范。", message, "不一致的代码规范会增加审阅和维护成本。",
                "按规则消息修改代码，或在团队策略中记录有理由的抑制。", AdapterSupport.moduleFor(project, relative),
                new SourceLocation(AdapterSupport.portable(relative), line, column, line, column),
                AdapterSupport.snippet(project, relative, line, line), VulnerabilityIdentifiers.EMPTY,
                null, List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    private Severity severity(String value) {
        return "error".equalsIgnoreCase(value) ? Severity.P2 : Severity.P3;
    }

    private int positive(String value, String name) throws IOException {
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 1) throw new NumberFormatException();
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IOException("invalid " + name);
        }
    }

    private int nonNegative(String value) {
        try { return Math.max(0, Integer.parseInt(value)); } catch (NumberFormatException exception) { return 0; }
    }

    private String required(String value, String name) throws IOException {
        if (value == null || value.isBlank()) throw new IOException("missing " + name);
        return value;
    }
}
