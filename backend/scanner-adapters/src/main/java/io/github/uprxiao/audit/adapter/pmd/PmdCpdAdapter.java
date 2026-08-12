package io.github.uprxiao.audit.adapter.pmd;

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
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public final class PmdCpdAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("pmd-cpd");
    public static final String TOOL_VERSION = PmdAdapter.TOOL_VERSION;
    private static final long MAX_REPORT_BYTES = 256L * 1024 * 1024;

    private final Path pmdHome;

    public PmdCpdAdapter(Path pmdHome) {
        this.pmdHome = Objects.requireNonNull(pmdHome).toAbsolutePath().normalize();
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "PMD CPD", false,
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
        if (!Files.isDirectory(pmdHome.resolve("lib"))) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "PMD_HOME_INVALID", pmdHome.toString());
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, ID);
        Files.createDirectories(context.engineOutputDirectory());
        Path report = context.engineOutputDirectory().resolve("report.xml");
        List<String> command = List.of(
                installation.executable().toString(), "-cp", pmdHome.resolve("lib/*").toString(),
                "net.sourceforge.pmd.cli.PmdCli", "cpd",
                "--dir", context.project().workspaceRoot().toString(), "--language", "java",
                "--minimum-tokens", "30", "--format", "xml", "--report-file", report.toString(),
                "--relativize-paths-with", context.project().workspaceRoot().toString(),
                "--no-fail-on-violation", "--no-fail-on-error");
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
                if (!"pmd-cpd".equals(document.getDocumentElement().getNodeName())) errors.add("REPORT_SCHEMA_INVALID");
            } catch (IOException exception) {
                errors.add("REPORT_XML_INVALID");
            }
        }
        return new ArtifactValidation(errors.isEmpty(), errors);
    }

    @Override
    public NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) throws IOException {
        ArtifactValidation validation = validate(artifacts);
        if (!validation.valid()) throw new IOException("PMD CPD artifacts are invalid: " + validation.errors());
        Document document = SecureXml.parse(artifacts.artifacts().get("report"));
        String version = document.getDocumentElement().getAttribute("pmdVersion");
        if (version.isBlank()) version = TOOL_VERSION;
        List<String> warnings = new ArrayList<>();
        NodeList errors = document.getElementsByTagName("error");
        for (int index = 0; index < errors.getLength(); index++) {
            warnings.add("CPD_PROCESSING_ERROR: " + ((Element) errors.item(index)).getAttribute("msg"));
        }
        List<Finding> findings = new ArrayList<>();
        NodeList duplications = document.getElementsByTagName("duplication");
        for (int index = 0; index < duplications.getLength(); index++) {
            try {
                findings.add(toFinding(context.project(), (Element) duplications.item(index), version, index));
            } catch (IOException | IllegalArgumentException exception) {
                warnings.add("CPD_ITEM_" + index + ": " + exception.getMessage());
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(findings,
                new EngineCoverage(ID.value(), status, modules, modules, modules, findings.size(),
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "CPD_PARTIAL_ERRORS",
                        "raw/pmd-cpd/report.xml"), warnings);
    }

    private Finding toFinding(ProjectContext project, Element duplication, String version, int index) throws IOException {
        NodeList files = duplication.getElementsByTagName("file");
        if (files.getLength() < 2) throw new IOException("duplication requires at least two occurrences");
        List<Occurrence> occurrences = new ArrayList<>();
        for (int position = 0; position < files.getLength(); position++) {
            Element file = (Element) files.item(position);
            Path relative = AdapterSupport.normalizeFindingPath(project, file.getAttribute("path"));
            int line = positive(file.getAttribute("line"), "line");
            int endLine = Math.max(line, positive(file.getAttribute("endline"), "endline"));
            int column = nonNegative(file.getAttribute("column"));
            int endColumn = Math.max(column, nonNegative(file.getAttribute("endcolumn")));
            occurrences.add(new Occurrence(relative, line, endLine, column, endColumn));
        }
        occurrences.sort(Comparator.comparing(value -> AdapterSupport.portable(value.path())));
        if (duplication.getElementsByTagName("codefragment").getLength() == 0) {
            throw new IOException("duplication is missing codefragment");
        }
        String code = duplication.getElementsByTagName("codefragment").item(0).getTextContent();
        String occurrenceKey = occurrences.stream()
                .map(value -> AdapterSupport.portable(value.path()) + ":" + value.line())
                .reduce((left, right) -> left + "|" + right).orElse("");
        String fingerprint = AdapterSupport.fingerprint("DUPLICATION|" + AdapterSupport.normalizedMessage(code) + "|" + occurrenceKey);
        Occurrence primary = occurrences.get(0);
        int lines = positive(duplication.getAttribute("lines"), "lines");
        int tokens = positive(duplication.getAttribute("tokens"), "tokens");
        List<Map<String, Object>> occurrenceEvidence = occurrences.stream()
                .map(value -> Map.<String, Object>of("path", AdapterSupport.portable(value.path()),
                        "startLine", value.line(), "endLine", value.endLine()))
                .toList();
        FindingEvidence evidence = new FindingEvidence(ID.value(), version, "CPD", Integer.toString(tokens),
                "raw/pmd-cpd/report.xml", "duplication:" + index,
                Map.of("lines", lines, "tokens", tokens, "occurrences", occurrenceEvidence));
        return new Finding(AdapterSupport.findingId(fingerprint), fingerprint, 1, IssueCategory.DUPLICATION,
                Severity.P3, Confidence.HIGH, "DUPLICATE_CODE", "检测到重复代码片段", "Duplicate code block",
                "多个位置包含相同或高度相似的代码片段。", "Found " + lines + " duplicated lines (" + tokens + " tokens)",
                "重复实现会增加同步修改和缺陷遗漏风险。", "提取公共方法、组件或模板，并保留必要的差异参数。",
                AdapterSupport.moduleFor(project, primary.path()),
                new SourceLocation(AdapterSupport.portable(primary.path()), primary.line(), primary.column(),
                        primary.endLine(), primary.endColumn()),
                AdapterSupport.snippet(project, primary.path(), primary.line(), primary.endLine()),
                VulnerabilityIdentifiers.EMPTY, null, List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
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
        try {
            return Math.max(0, Integer.parseInt(value));
        } catch (NumberFormatException exception) {
            return 0;
        }
    }

    private record Occurrence(Path path, int line, int endLine, int column, int endColumn) {
    }
}
