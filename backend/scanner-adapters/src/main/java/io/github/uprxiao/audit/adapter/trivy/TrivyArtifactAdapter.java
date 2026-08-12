package io.github.uprxiao.audit.adapter.trivy;

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
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Scans the immutable CycloneDX asset produced by the cyclonedx logical engine. */
public final class TrivyArtifactAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("trivy-artifact");
    public static final String TOOL_VERSION = TrivyRepositoryAdapter.TOOL_VERSION;
    private static final long MAX_REPORT_BYTES = 512L * 1024 * 1024;
    private static final Duration STALE_AFTER = Duration.ofDays(7);
    private final Path cacheDirectory;
    private final ObjectMapper json;
    private final DependencyFindingSupport findings = new DependencyFindingSupport();

    public TrivyArtifactAdapter(Path cacheDirectory) {
        this(cacheDirectory, new ObjectMapper());
    }

    TrivyArtifactAdapter(Path cacheDirectory, ObjectMapper json) {
        this.cacheDirectory = Objects.requireNonNull(cacheDirectory).toAbsolutePath().normalize();
        this.json = Objects.requireNonNull(json);
    }

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "Trivy Artifact", true,
                new ResourceRequest(ResourceClass.HEAVY, 4, 3072), Duration.ofMinutes(20),
                Set.of(CycloneDxId.VALUE));
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return unavailable("TOOL_UNAVAILABLE", "Trivy executable is unavailable");
        }
        if (!TOOL_VERSION.equals(installation.version())) {
            return unavailable("TOOL_VERSION_MISMATCH", installation.version());
        }
        if (databaseMetadata().isEmpty()) {
            return unavailable("VULNERABILITY_DATABASE_UNAVAILABLE", "Trivy DB metadata is unavailable or invalid");
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, ID);
        DatabaseMetadata database = databaseMetadata().orElseThrow(() ->
                new IOException("VULNERABILITY_DATABASE_UNAVAILABLE"));
        Files.createDirectories(context.engineOutputDirectory());
        Path sbom = sbomInput(context);
        if (!Files.isRegularFile(sbom)) throw new IOException("CYCLONEDX_SBOM_UNAVAILABLE: " + sbom);
        Path report = context.engineOutputDirectory().resolve("report.json");
        List<String> command = List.of(
                installation.executable().toString(), "sbom", "--scanners", "vuln,license",
                "--format", "json", "--output", report.toString(), "--cache-dir", cacheDirectory.toString(),
                "--skip-db-update", "--skip-java-db-update", "--skip-version-check", "--offline-scan",
                "--quiet", "--no-progress", "--timeout", "15m", "--exit-code", "0", sbom.toString());
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
        if (report == null || !Files.isRegularFile(report)) errors.add("REPORT_MISSING");
        else if (Files.size(report) > MAX_REPORT_BYTES) errors.add("REPORT_TOO_LARGE");
        else {
            try {
                JsonNode root = json.readTree(report.toFile());
                if (root == null || root.path("SchemaVersion").asInt(0) < 2 || !root.path("Results").isArray()) {
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
        if (!validation.valid()) throw new IOException("Trivy artifact report is invalid: " + validation.errors());
        DatabaseMetadata database = databaseMetadata().orElseThrow(() ->
                new IOException("VULNERABILITY_DATABASE_UNAVAILABLE"));
        JsonNode root = json.readTree(artifacts.artifacts().get("report").toFile());
        List<Finding> normalized = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        if (database.stale()) warnings.add("TRIVY_DATABASE_STALE: " + database.updatedAt());
        root.path("Errors").forEach(error -> warnings.add("TRIVY_ERROR: " + error.asText(error.toString())));
        int rawCount = 0;
        for (JsonNode result : root.path("Results")) {
            result.path("Errors").forEach(error -> warnings.add("TRIVY_RESULT_ERROR: " + error.asText(error.toString())));
            for (JsonNode vulnerability : result.path("Vulnerabilities")) {
                try {
                    normalized.add(toFinding(context.project(), result, vulnerability, database, rawCount));
                } catch (IllegalArgumentException exception) {
                    warnings.add("TRIVY_ARTIFACT_ITEM_" + rawCount + ": " + exception.getMessage());
                }
                rawCount++;
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(normalized,
                new EngineCoverage(ID.value(), status, modules, modules, modules, rawCount,
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "TRIVY_ARTIFACT_PARTIAL",
                        "raw/trivy-artifact/report.json"), warnings);
    }

    private Finding toFinding(ProjectContext project, JsonNode result, JsonNode vulnerability,
                              DatabaseMetadata database, int index) {
        String id = required(vulnerability, "VulnerabilityID");
        String name = required(vulnerability, "PkgName");
        String current = required(vulnerability, "InstalledVersion");
        String purl = vulnerability.path("PkgIdentifier").path("PURL").asText("");
        if (purl.isBlank()) purl = packagePurl(result, vulnerability.path("PkgID").asText(""), name);
        String target = result.path("Target").asText(project.manifest().rootPom());
        String module = project.manifest().modules().isEmpty() ? "" : project.manifest().modules().get(0).artifactId();
        List<String> fixed = commaSeparated(vulnerability.path("FixedVersion").asText(""));
        List<String> aliases = DependencyFindingSupport.strings(vulnerability.path("VendorIDs"));
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("status", vulnerability.path("Status").asText(""));
        properties.put("primaryUrl", vulnerability.path("PrimaryURL").asText(""));
        properties.put("target", target);
        properties.put("packagePath", vulnerability.path("PkgPath").asText(""));
        properties.put("databaseUpdatedAt", database.updatedAt().toString());
        return findings.finding(ID.value(), TOOL_VERSION, "raw/trivy-artifact/report.json", id + ":" + index,
                id, aliases, DependencyFindingSupport.strings(vulnerability.path("CweIDs")), purl, name, current,
                module, "", false, List.of(target, vulnerability.path("PkgPath").asText(name)), fixed,
                vulnerability.path("Severity").asText("UNKNOWN"), cvss(vulnerability),
                vulnerability.path("KnownExploited").asBoolean(false),
                vulnerability.path("Title").asText(id), vulnerability.path("Description").asText(""), properties);
    }

    private String packagePurl(JsonNode result, String packageId, String name) {
        for (JsonNode pkg : result.path("Packages")) {
            if (packageId.equals(pkg.path("ID").asText()) || name.equals(pkg.path("Name").asText())) {
                String purl = pkg.path("Identifier").path("PURL").asText("");
                if (purl.isBlank()) purl = pkg.path("PkgIdentifier").path("PURL").asText("");
                if (!purl.isBlank()) return purl;
            }
        }
        return "";
    }

    private Double cvss(JsonNode vulnerability) {
        Double best = null;
        for (JsonNode source : vulnerability.path("CVSS")) {
            Double value = DependencyFindingSupport.decimal(source.path("V3Score"));
            if (value == null) value = DependencyFindingSupport.decimal(source.path("V4Score"));
            if (value != null && (best == null || value > best)) best = value;
        }
        return best;
    }

    private Path sbomInput(ScanContext context) throws IOException {
        Path rawRoot = context.engineOutputDirectory().getParent();
        if (rawRoot == null) throw new IOException("engine output directory has no raw parent");
        Path candidate = rawRoot.resolve("cyclonedx/sbom/bom.json").normalize();
        if (!candidate.startsWith(rawRoot.normalize())) throw new IOException("unsafe CycloneDX SBOM path");
        return candidate;
    }

    private java.util.Optional<DatabaseMetadata> databaseMetadata() {
        Path metadata = cacheDirectory.resolve("db/metadata.json");
        Path database = cacheDirectory.resolve("db/trivy.db");
        try {
            if (!Files.isRegularFile(metadata) || !Files.isRegularFile(database) || Files.size(database) < 1) {
                return java.util.Optional.empty();
            }
        } catch (IOException exception) {
            return java.util.Optional.empty();
        }
        try {
            JsonNode root = json.readTree(metadata.toFile());
            if (root.path("Version").asInt(0) < 1) return java.util.Optional.empty();
            Instant updatedAt = Instant.parse(root.path("UpdatedAt").asText());
            return java.util.Optional.of(new DatabaseMetadata(updatedAt,
                    updatedAt.plus(STALE_AFTER).isBefore(Instant.now())));
        } catch (IOException | DateTimeParseException exception) {
            return java.util.Optional.empty();
        }
    }

    private List<String> commaSeparated(String value) {
        if (value == null || value.isBlank()) return List.of();
        return DependencyFindingSupport.distinct(List.of(value.split(",\\s*")));
    }

    private String required(JsonNode node, String field) {
        String value = node.path(field).asText("").trim();
        if (value.isBlank()) throw new IllegalArgumentException("missing field " + field);
        return value;
    }

    private Applicability unavailable(String code, String message) {
        return new Applicability(Applicability.Status.UNAVAILABLE, code, message);
    }

    private record DatabaseMetadata(Instant updatedAt, boolean stale) { }

    private static final class CycloneDxId {
        private static final EngineId VALUE = new EngineId("cyclonedx");
    }
}
