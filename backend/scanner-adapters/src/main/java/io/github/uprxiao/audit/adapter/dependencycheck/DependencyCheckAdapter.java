package io.github.uprxiao.audit.adapter.dependencycheck;

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
import java.util.Objects;
import java.util.Set;

/** OWASP Dependency-Check 12.2.2 CLI adapter with an explicit local-database precondition. */
public final class DependencyCheckAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("dependency-check");
    public static final String TOOL_VERSION = "12.2.2";
    private static final long MAX_REPORT_BYTES = 512L * 1024 * 1024;

    private final Path dataDirectory;
    private final ObjectMapper json;
    private final DependencyFindingSupport findings = new DependencyFindingSupport();

    public DependencyCheckAdapter(Path dataDirectory) {
        this(dataDirectory, new ObjectMapper());
    }

    DependencyCheckAdapter(Path dataDirectory, ObjectMapper json) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory).toAbsolutePath().normalize();
        this.json = Objects.requireNonNull(json);
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "OWASP Dependency-Check", true,
                new ResourceRequest(ResourceClass.HEAVY, 4, 4096), Duration.ofMinutes(30), Set.of());
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return unavailable("TOOL_UNAVAILABLE", "Dependency-Check CLI is unavailable");
        }
        if (!TOOL_VERSION.equals(installation.version())) {
            return unavailable("TOOL_VERSION_MISMATCH", installation.version());
        }
        if (!hasUsableDatabase()) {
            return unavailable("VULNERABILITY_DATABASE_UNAVAILABLE",
                    "Dependency-Check data directory has no initialized odc database");
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, ID);
        if (!hasUsableDatabase()) throw new IOException("VULNERABILITY_DATABASE_UNAVAILABLE");
        Files.createDirectories(context.engineOutputDirectory());
        Files.createDirectories(dataDirectory);
        List<String> command = List.of(
                installation.executable().toString(),
                "--project", safeProjectName(context.project()),
                "--scan", context.project().workspaceRoot().toString(),
                "--format", "JSON", "--prettyPrint",
                "--out", context.engineOutputDirectory().toString(),
                "--data", dataDirectory.toString(), "--noupdate",
                "--disableOssIndex", "--disableNodeAudit", "--disableYarnAudit", "--disablePnpmAudit",
                "--failOnCVSS", "11");
        Map<String, String> environment = new LinkedHashMap<>(
                AdapterSupport.isolatedEnvironment(context.engineOutputDirectory(), installation.executable()));
        environment.put("JAVA_HOME", Path.of(System.getProperty("java.home")).toAbsolutePath().normalize().toString());
        return new ExecutionSpec(ID, command, context.engineOutputDirectory(), environment,
                descriptor().defaultTimeout(), descriptor().resources(),
                Set.of(new ExpectedArtifact("dependency-check-report.json", true, MAX_REPORT_BYTES)),
                RedactionPolicy.NONE);
    }

    @Override
    public ArtifactValidation validate(RawArtifactSet artifacts) throws IOException {
        List<String> errors = new ArrayList<>();
        if (!ID.equals(artifacts.engine())) errors.add("ENGINE_MISMATCH");
        if (artifacts.execution().status() != ExecutionResult.Status.SUCCEEDED) {
            errors.add("EXECUTION_" + artifacts.execution().status());
        }
        Path report = report(artifacts);
        if (report == null || !Files.isRegularFile(report)) errors.add("REPORT_MISSING");
        else if (Files.size(report) > MAX_REPORT_BYTES) errors.add("REPORT_TOO_LARGE");
        else {
            try {
                JsonNode root = json.readTree(report.toFile());
                if (root == null || !root.path("dependencies").isArray() || !root.path("scanInfo").isObject()) {
                    errors.add("REPORT_SCHEMA_INVALID");
                } else if (!hasReportDatabaseEvidence(root)) {
                    errors.add("VULNERABILITY_DATABASE_UNAVAILABLE");
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
        if (!validation.valid()) throw new IOException("Dependency-Check artifacts are invalid: " + validation.errors());
        JsonNode root = json.readTree(report(artifacts).toFile());
        List<Finding> normalized = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        root.path("scanInfo").path("analysisExceptions").forEach(value ->
                warnings.add("DEPENDENCY_CHECK_ANALYSIS_EXCEPTION: " + value.asText(value.toString())));
        String databaseEvidence = databaseEvidence(root);
        int rawCount = 0;
        for (JsonNode dependency : root.path("dependencies")) {
            for (JsonNode vulnerability : dependency.path("vulnerabilities")) {
                try {
                    normalized.add(toFinding(context.project(), dependency, vulnerability, databaseEvidence, rawCount));
                } catch (IllegalArgumentException exception) {
                    warnings.add("DEPENDENCY_CHECK_ITEM_" + rawCount + ": " + exception.getMessage());
                }
                rawCount++;
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(normalized,
                new EngineCoverage(ID.value(), status, modules, modules, modules, rawCount,
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "DEPENDENCY_CHECK_PARTIAL",
                        "raw/dependency-check/dependency-check-report.json"), warnings);
    }

    private Finding toFinding(ProjectContext project, JsonNode dependency, JsonNode vulnerability,
                              String databaseEvidence, int index) {
        String vulnerabilityId = required(vulnerability, "name");
        String purl = mavenPurl(dependency.path("packages"));
        String packageName = packageName(purl, dependency.path("fileName").asText(""));
        String version = version(purl, dependency.path("version").asText(""));
        String module = module(project, dependency);
        List<String> path = DependencyFindingSupport.strings(dependency.path("projectReferences"));
        if (path.isEmpty()) path = List.of(module.isBlank() ? project.manifest().rootPom() : module);
        List<String> aliases = new ArrayList<>();
        vulnerability.path("references").forEach(reference -> {
            String name = reference.path("name").asText("");
            if (name.startsWith("CVE-") || name.startsWith("GHSA-")) aliases.add(name);
        });
        Double cvss = firstDecimal(vulnerability.path("cvssv4").path("baseScore"),
                vulnerability.path("cvssv3").path("baseScore"), vulnerability.path("cvssv2").path("score"));
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("source", vulnerability.path("source").asText(""));
        properties.put("filePath", dependency.path("filePath").asText(""));
        properties.put("databaseEvidence", databaseEvidence);
        properties.put("vulnerabilityPublishedDate", vulnerability.path("publishedDate").asText(""));
        return findings.finding(ID.value(), TOOL_VERSION, "raw/dependency-check/dependency-check-report.json",
                vulnerabilityId + ":" + index, vulnerabilityId, aliases,
                DependencyFindingSupport.strings(vulnerability.path("cwes")), purl, packageName, version,
                module, "", false, path, fixedVersions(vulnerability),
                vulnerability.path("severity").asText("UNKNOWN"), cvss,
                vulnerability.path("knownExploitedVulnerability").isObject(),
                vulnerability.path("name").asText(vulnerabilityId),
                vulnerability.path("description").asText(""), properties);
    }

    private boolean hasUsableDatabase() {
        if (!Files.isDirectory(dataDirectory)) return false;
        try (var files = Files.list(dataDirectory)) {
            return files.anyMatch(path -> path.getFileName().toString().startsWith("odc")
                    && path.getFileName().toString().contains(".mv.db") && isNonEmpty(path));
        } catch (IOException ignored) {
            return false;
        }
    }

    private boolean hasReportDatabaseEvidence(JsonNode root) {
        JsonNode sources = root.path("scanInfo").path("dataSource");
        if (!sources.isArray() || sources.isEmpty()) return false;
        for (JsonNode source : sources) {
            if (!source.path("name").asText("").isBlank() && !source.path("timestamp").asText("").isBlank()) return true;
        }
        return false;
    }

    private boolean isNonEmpty(Path path) {
        try { return Files.isRegularFile(path) && Files.size(path) > 0; }
        catch (IOException ignored) { return false; }
    }

    private Path report(RawArtifactSet artifacts) {
        Path report = artifacts.artifacts().get("report");
        return report == null ? artifacts.artifacts().get("dependency-check-report") : report;
    }

    private String safeProjectName(ProjectContext project) {
        String value = project.manifest().modules().isEmpty() ? "java-audit"
                : project.manifest().modules().get(0).artifactId();
        return value.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private String packageName(String purl, String fallback) {
        if (purl.startsWith("pkg:maven/")) {
            String identity = purl.substring("pkg:maven/".length()).split("[@?]", 2)[0];
            String[] parts = identity.split("/", 2);
            if (parts.length == 2) return parts[0] + ":" + parts[1];
        }
        return fallback;
    }

    private String mavenPurl(JsonNode packages) {
        for (JsonNode value : packages) {
            String id = value.path("id").asText("");
            if (id.startsWith("pkg:maven/")) return id;
        }
        return "";
    }

    private String version(String purl, String fallback) {
        int at = purl.indexOf('@');
        if (at >= 0) return purl.substring(at + 1).split("\\?", 2)[0];
        return fallback;
    }

    private String module(ProjectContext project, JsonNode dependency) {
        String reference = dependency.path("projectReferences").isArray()
                && !dependency.path("projectReferences").isEmpty()
                ? dependency.path("projectReferences").get(0).asText("") : "";
        if (!reference.isBlank()) return reference;
        return project.manifest().modules().isEmpty() ? "" : project.manifest().modules().get(0).artifactId();
    }

    private List<String> fixedVersions(JsonNode vulnerability) {
        List<String> versions = DependencyFindingSupport.strings(vulnerability.path("fixedVersions"));
        if (!versions.isEmpty()) return versions;
        return List.of();
    }

    private String databaseEvidence(JsonNode root) {
        List<String> values = new ArrayList<>();
        root.path("scanInfo").path("dataSource").forEach(source -> values.add(
                source.path("name").asText("") + "@" + source.path("timestamp").asText("")));
        return String.join(",", values);
    }

    private Double firstDecimal(JsonNode... nodes) {
        for (JsonNode node : nodes) {
            Double value = DependencyFindingSupport.decimal(node);
            if (value != null) return value;
        }
        return null;
    }

    private String required(JsonNode node, String field) {
        String value = node.path(field).asText("").trim();
        if (value.isBlank()) throw new IllegalArgumentException("missing field " + field);
        return value;
    }

    private Applicability unavailable(String code, String message) {
        return new Applicability(Applicability.Status.UNAVAILABLE, code, message);
    }
}
