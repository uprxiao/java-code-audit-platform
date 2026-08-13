package io.github.uprxiao.audit.adapter.osv;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.adapter.support.AdapterSupport;
import io.github.uprxiao.audit.adapter.support.DependencyFindingSupport;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.Finding;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** OSV-Scanner v2 source adapter. Exit code 1 means findings; 128+ means scanner/network failure. */
public final class OsvScannerAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("osv-scanner");
    public static final String TOOL_VERSION = "2.3.8";
    private static final long MAX_REPORT_BYTES = 512L * 1024 * 1024;
    private final ObjectMapper json;
    private final DependencyFindingSupport findings = new DependencyFindingSupport();

    public OsvScannerAdapter() {
        this(new ObjectMapper());
    }

    OsvScannerAdapter(ObjectMapper json) {
        this.json = json;
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "OSV-Scanner", true,
                new ResourceRequest(ResourceClass.MEDIUM, 2, 2048), Duration.ofMinutes(15), Set.of());
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "TOOL_UNAVAILABLE", "OSV-Scanner is unavailable");
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
        Path report = context.engineOutputDirectory().resolve("report.json");
        List<String> command = List.of(
                installation.executable().toString(), "scan", "source", "--recursive",
                "--no-resolve", "--allow-no-lockfiles",
                "--experimental-exclude", "g:**/target/**",
                "--experimental-exclude", "g:**/build/**",
                "--experimental-exclude", "g:**/.m2/**",
                "--experimental-exclude", "g:**/.gradle/**",
                "--experimental-exclude", "g:**/node_modules/**",
                "--experimental-exclude", "g:**/data/cache/**",
                "--format", "json", "--output-file", report.toString(),
                "--verbosity", "warn", context.project().workspaceRoot().toString());
        return new ExecutionSpec(ID, command, context.engineOutputDirectory(),
                AdapterSupport.isolatedEnvironment(context.engineOutputDirectory(), installation.executable()),
                descriptor().defaultTimeout(), descriptor().resources(),
                Set.of(new ExpectedArtifact("report.json", true, MAX_REPORT_BYTES)), RedactionPolicy.NONE);
    }

    @Override
    public ArtifactValidation validate(RawArtifactSet artifacts) throws IOException {
        List<String> errors = new ArrayList<>();
        if (!ID.equals(artifacts.engine())) errors.add("ENGINE_MISMATCH");
        ExecutionResult execution = artifacts.execution();
        boolean expectedExit = (execution.status() == ExecutionResult.Status.SUCCEEDED
                && (execution.exitCode() == null || execution.exitCode() == 0))
                || (execution.status() == ExecutionResult.Status.FAILED
                && Integer.valueOf(1).equals(execution.exitCode()));
        if (!expectedExit) errors.add("EXECUTION_" + execution.status());
        Path report = artifacts.artifacts().get("report");
        if (report == null || !Files.isRegularFile(report)) errors.add("REPORT_MISSING");
        else if (Files.size(report) > MAX_REPORT_BYTES) errors.add("REPORT_TOO_LARGE");
        else {
            try {
                JsonNode root = json.readTree(report.toFile());
                JsonNode results = root == null ? null : root.get("results");
                if (results == null || (!results.isArray() && !results.isNull())) {
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
        if (!validation.valid()) throw new IOException("OSV artifacts are invalid: " + validation.errors());
        JsonNode root = json.readTree(artifacts.artifacts().get("report").toFile());
        List<Finding> normalized = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        int rawCount = 0;
        JsonNode results = root.get("results");
        for (JsonNode result : results.isNull() ? List.<JsonNode>of() : results) {
            String source = result.path("source").path("path").asText("");
            for (JsonNode pkg : result.path("packages")) {
                JsonNode coordinates = pkg.path("package");
                List<JsonNode> groups = new ArrayList<>();
                pkg.path("groups").forEach(groups::add);
                int vulnerabilityIndex = 0;
                for (JsonNode vulnerability : pkg.path("vulnerabilities")) {
                    try {
                        normalized.add(toFinding(context.project(), source, coordinates, groups,
                                vulnerability, vulnerabilityIndex, rawCount));
                    } catch (IllegalArgumentException exception) {
                        warnings.add("OSV_ITEM_" + rawCount + ": " + exception.getMessage());
                    }
                    rawCount++;
                    vulnerabilityIndex++;
                }
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(normalized,
                new EngineCoverage(ID.value(), status, modules, modules, modules, rawCount,
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "OSV_PARTIAL",
                        "raw/osv-scanner/report.json"), warnings);
    }

    private Finding toFinding(ProjectContext project, String source, JsonNode coordinates, List<JsonNode> groups,
                              JsonNode vulnerability, int vulnerabilityIndex, int rawIndex) {
        String id = required(vulnerability, "id");
        String name = required(coordinates, "name");
        String version = required(coordinates, "version");
        String purl = purl(vulnerability);
        List<String> aliases = DependencyFindingSupport.strings(vulnerability.path("aliases"));
        List<String> fixed = DependencyFindingSupport.fixedVersions(vulnerability);
        List<String> cwes = DependencyFindingSupport.strings(vulnerability.path("database_specific").path("cwe_ids"));
        String sourcePath = portableSource(project, source);
        String module = module(project, sourcePath);
        JsonNode group = group(groups, id, vulnerabilityIndex);
        Double cvss = DependencyFindingSupport.decimal(group.path("max_severity"));
        String engineSeverity = vulnerability.path("database_specific").path("severity").asText(
                cvss == null ? "UNKNOWN" : cvss >= 9 ? "CRITICAL" : cvss >= 7 ? "HIGH" : cvss >= 4 ? "MEDIUM" : "LOW");
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("sourcePath", sourcePath);
        properties.put("dataSource", "https://api.osv.dev");
        properties.put("ecosystem", coordinates.path("ecosystem").asText(""));
        properties.put("published", vulnerability.path("published").asText(""));
        properties.put("modified", vulnerability.path("modified").asText(""));
        return findings.finding(ID.value(), TOOL_VERSION, "raw/osv-scanner/report.json", id + ":" + rawIndex,
                id, aliases, cwes, purl, name, version, module, "", false,
                List.of(sourcePath), fixed, engineSeverity, cvss, false,
                vulnerability.path("summary").asText(id), vulnerability.path("details").asText(""), properties);
    }

    private String purl(JsonNode vulnerability) {
        for (JsonNode affected : vulnerability.path("affected")) {
            String value = affected.path("package").path("purl").asText("");
            if (!value.isBlank()) return value;
        }
        return "";
    }

    private JsonNode group(List<JsonNode> groups, String id, int fallbackIndex) {
        for (JsonNode group : groups) {
            for (JsonNode value : group.path("ids")) if (id.equals(value.asText())) return group;
            for (JsonNode value : group.path("aliases")) if (id.equals(value.asText())) return group;
        }
        return fallbackIndex < groups.size() ? groups.get(fallbackIndex) : json.createObjectNode();
    }

    private String module(ProjectContext project, String portable) {
        try {
            return AdapterSupport.moduleFor(project, Path.of(portable));
        } catch (RuntimeException ignored) {
            return project.manifest().modules().isEmpty() ? "" : project.manifest().modules().get(0).artifactId();
        }
    }

    private String portableSource(ProjectContext project, String source) {
        if (source == null || source.isBlank()) {
            throw new IllegalArgumentException("OSV source path is missing");
        }
        try {
            return AdapterSupport.portable(AdapterSupport.normalizeFindingPath(project, source));
        } catch (IOException exception) {
            throw new IllegalArgumentException("OSV source path is unsafe: " + source, exception);
        }
    }

    private String required(JsonNode node, String field) {
        String value = node.path(field).asText("").trim();
        if (value.isBlank()) throw new IllegalArgumentException("missing field " + field);
        return value;
    }
}
