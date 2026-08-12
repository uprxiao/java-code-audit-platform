package io.github.uprxiao.audit.adapter.cyclonedx;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.adapter.support.AdapterSupport;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.intake.MavenArgumentValidator;
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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Generates a CycloneDX 1.6 JSON asset. SBOM components are inventory, never findings by themselves. */
public final class CycloneDxAdapter implements ScannerAdapter {

    public static final EngineId ID = new EngineId("cyclonedx");
    public static final String TOOL_VERSION = "2.9.3";
    public static final String MAVEN_COORDINATE =
            "org.cyclonedx:cyclonedx-maven-plugin:" + TOOL_VERSION + ":makeAggregateBom";
    private static final long MAX_SBOM_BYTES = 512L * 1024 * 1024;
    private final ObjectMapper json = new ObjectMapper();
    private final MavenArgumentValidator mavenArguments = new MavenArgumentValidator();

    @Override
    public EngineDescriptor descriptor() {
        return new EngineDescriptor(ID, "CycloneDX Maven SBOM", true,
                new ResourceRequest(ResourceClass.HEAVY, 4, 3072), Duration.ofMinutes(20), Set.of());
    }

    @Override
    public Applicability checkApplicability(ProjectContext project, ToolContext tools) {
        ToolContext.ToolInstallation installation = tools.installations().get(ID);
        if (installation == null || !installation.available()) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "MAVEN_UNAVAILABLE", "Maven is unavailable");
        }
        if (!TOOL_VERSION.equals(installation.version())) {
            return new Applicability(Applicability.Status.UNAVAILABLE, "PLUGIN_VERSION_MISMATCH", installation.version());
        }
        Path rootPom = project.resolveProjectPath(project.manifest().rootPom());
        if (!Files.isRegularFile(rootPom)) {
            return new Applicability(Applicability.Status.NOT_APPLICABLE, "ROOT_POM_MISSING", rootPom.toString());
        }
        return Applicability.applicable();
    }

    @Override
    public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws IOException {
        ToolContext.ToolInstallation installation = AdapterSupport.requireInstallation(tools, ID);
        Path sbomDirectory = Files.createDirectories(context.engineOutputDirectory().resolve("sbom"));
        mavenArguments.validate(context.mavenProfiles(), context.mavenProperties());
        List<String> command = new ArrayList<>(List.of(
                installation.executable().toString(), "--batch-mode", "--no-transfer-progress",
                "--file", context.project().resolveProjectPath(context.project().manifest().rootPom()).toString()));
        Set<Integer> sensitiveArguments = new HashSet<>();
        if (!context.mavenProfiles().isEmpty()) command.add("-P" + String.join(",", context.mavenProfiles()));
        for (Map.Entry<String, String> property : new TreeMap<>(context.mavenProperties()).entrySet()) {
            int index = command.size();
            command.add("-D" + property.getKey() + "=" + property.getValue());
            if (mavenArguments.isSensitiveProperty(property.getKey())) sensitiveArguments.add(index);
        }
        command.addAll(List.of(
                MAVEN_COORDINATE, "-DskipTests", "-DoutputFormat=json", "-DoutputName=bom",
                "-DoutputDirectory=" + sbomDirectory,
                "-Dcyclonedx.skipAttach=true", "-DincludeBomSerialNumber=true"));
        Map<String, String> environment = new LinkedHashMap<>(
                AdapterSupport.isolatedEnvironment(context.engineOutputDirectory(), installation.executable()));
        environment.put("JAVA_HOME", Path.of(System.getProperty("java.home")).toAbsolutePath().normalize().toString());
        return new ExecutionSpec(ID, command, context.engineOutputDirectory(), environment,
                descriptor().defaultTimeout(), descriptor().resources(),
                Set.of(new ExpectedArtifact("sbom/bom.json", true, MAX_SBOM_BYTES)),
                new RedactionPolicy(sensitiveArguments, Set.of()));
    }

    @Override
    public ArtifactValidation validate(RawArtifactSet artifacts) throws IOException {
        List<String> errors = new ArrayList<>();
        if (!ID.equals(artifacts.engine())) errors.add("ENGINE_MISMATCH");
        if (artifacts.execution().status() != ExecutionResult.Status.SUCCEEDED) {
            errors.add("EXECUTION_" + artifacts.execution().status());
        }
        Path sbom = sbom(artifacts);
        if (sbom == null || !Files.isRegularFile(sbom)) errors.add("SBOM_MISSING");
        else if (Files.size(sbom) > MAX_SBOM_BYTES) errors.add("SBOM_TOO_LARGE");
        else {
            try {
                JsonNode root = json.readTree(sbom.toFile());
                if (root == null || !"CycloneDX".equals(root.path("bomFormat").asText())
                        || root.path("specVersion").asText("").isBlank()
                        || !root.path("components").isArray() || !root.path("dependencies").isArray()) {
                    errors.add("SBOM_SCHEMA_INVALID");
                }
            } catch (IOException exception) {
                errors.add("SBOM_JSON_INVALID");
            }
        }
        return new ArtifactValidation(errors.isEmpty(), errors);
    }

    @Override
    public NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) throws IOException {
        ArtifactValidation validation = validate(artifacts);
        if (!validation.valid()) throw new IOException("CycloneDX artifacts are invalid: " + validation.errors());
        JsonNode root = json.readTree(sbom(artifacts).toFile());
        List<String> warnings = new ArrayList<>();
        int componentCount = 0;
        for (JsonNode component : root.path("components")) {
            componentCount++;
            if (component.path("name").asText("").isBlank() || component.path("version").asText("").isBlank()
                    || component.path("purl").asText("").isBlank()) {
                warnings.add("SBOM_COMPONENT_" + componentCount + "_INCOMPLETE");
            }
        }
        int modules = context.project().manifest().modules().size();
        EngineStatus status = warnings.isEmpty() ? EngineStatus.SUCCEEDED : EngineStatus.PARTIAL;
        return new NormalizationResult(List.of(),
                new EngineCoverage(ID.value(), status, modules, modules, modules, 0,
                        artifacts.execution().duration(), warnings.isEmpty() ? "" : "SBOM_PARTIAL",
                        "sbom/bom.json"), warnings);
    }

    private Path sbom(RawArtifactSet artifacts) {
        Path value = artifacts.artifacts().get("sbom");
        return value == null ? artifacts.artifacts().get("report") : value;
    }
}
