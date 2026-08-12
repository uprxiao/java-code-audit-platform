package io.github.uprxiao.audit.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Verifies every non-Semgrep Quick tool against its immutable pack metadata and version output. */
final class QuickToolIntegrityChecker {

    private final AuditRuntimePaths paths;
    private final LocalProcessExecutionBackend processes;
    private final ObjectMapper json;
    private final Clock clock;

    QuickToolIntegrityChecker(
            AuditRuntimePaths paths,
            LocalProcessExecutionBackend processes,
            ObjectMapper json,
            Clock clock) {
        this.paths = paths;
        this.processes = processes;
        this.json = json;
        this.clock = clock;
    }

    List<ToolInstallationHealth> checkAll() throws IOException, InterruptedException {
        return List.of(
                check("gitleaks", paths.quickToolRoot().resolve("gitleaks"), paths.gitleaksExecutable(), "8.30.1",
                        List.of(paths.gitleaksExecutable().toString(), "version")),
                check("pmd", paths.quickToolRoot().resolve("pmd"), paths.javaExecutable(), "7.26.0",
                        List.of(paths.javaExecutable().toString(), "-cp", paths.pmdHome().resolve("lib/*").toString(),
                                "net.sourceforge.pmd.cli.PmdCli", "--version")),
                check("pmd-cpd", paths.quickToolRoot().resolve("pmd"), paths.javaExecutable(), "7.26.0",
                        List.of(paths.javaExecutable().toString(), "-cp", paths.pmdHome().resolve("lib/*").toString(),
                                "net.sourceforge.pmd.cli.PmdCli", "--version")),
                check("checkstyle", paths.quickToolRoot().resolve("checkstyle"), paths.javaExecutable(), "12.3.1",
                        List.of(paths.javaExecutable().toString(), "-jar", paths.checkstyleJar().toString(), "--version")),
                check("trivy-repository", paths.quickToolRoot().resolve("trivy"), paths.trivyExecutable(), "0.73.0",
                        List.of(paths.trivyExecutable().toString(), "--version")));
    }

    private ToolInstallationHealth check(
            String engineId,
            Path toolDirectory,
            Path executable,
            String expectedVersion,
            List<String> versionCommand) throws IOException, InterruptedException {
        Path metadataPath = toolDirectory.resolve("pack-metadata.json");
        if (!Files.isRegularFile(metadataPath)) {
            return unavailable(engineId, executable, "TOOL_METADATA_MISSING", metadataPath.toString());
        }
        JsonNode metadata;
        try {
            metadata = json.readTree(metadataPath.toFile());
        } catch (IOException exception) {
            return unavailable(engineId, executable, "TOOL_METADATA_INVALID", exception.getMessage());
        }
        String metadataVersion = metadata.path("version").asText();
        if (!expectedVersion.equals(metadataVersion)) {
            return incompatible(engineId, executable, "TOOL_VERSION_MISMATCH",
                    "metadata=" + metadataVersion + ", expected=" + expectedVersion);
        }
        Path entrypoint = toolDirectory.resolve(metadata.path("entrypoint").asText()).normalize();
        if (!entrypoint.startsWith(toolDirectory) || !Files.isRegularFile(entrypoint)) {
            return unavailable(engineId, executable, "EXECUTABLE_NOT_FOUND", entrypoint.toString());
        }
        if (!Files.isRegularFile(executable) || !Files.isExecutable(executable)) {
            return unavailable(engineId, executable, "EXECUTABLE_NOT_FOUND", executable.toString());
        }
        String actualSha = sha256(entrypoint);
        String expectedSha = metadata.path("entrypointSha256").asText();
        if (expectedSha.isBlank() || !expectedSha.equalsIgnoreCase(actualSha)) {
            return incompatible(engineId, executable, "TOOL_SHA256_MISMATCH", "actual=" + actualSha);
        }
        Path probeDirectory = paths.dataRoot().resolve("health/probes").resolve(engineId);
        Files.createDirectories(probeDirectory);
        ExecutionResult execution = processes.execute(versionSpec(engineId, versionCommand, probeDirectory),
                CancellationToken.NONE);
        if (execution.status() != ExecutionResult.Status.SUCCEEDED) {
            return unavailable(engineId, executable, "VERSION_COMMAND_FAILED", execution.message());
        }
        String output = Files.readString(execution.stdout()) + "\n" + Files.readString(execution.stderr());
        if (!output.toLowerCase(Locale.ROOT).contains(expectedVersion.toLowerCase(Locale.ROOT))) {
            return incompatible(engineId, executable, "TOOL_VERSION_MISMATCH", output.strip());
        }
        return new ToolInstallationHealth(
                engineId, "AVAILABLE", expectedVersion, executable, actualSha, "", "", clock.instant());
    }

    private ExecutionSpec versionSpec(String id, List<String> command, Path workingDirectory) {
        List<String> pathEntries = new ArrayList<>();
        pathEntries.add(Path.of(command.get(0)).getParent().toString());
        pathEntries.add("/usr/bin");
        pathEntries.add("/bin");
        return new ExecutionSpec(
                new EngineId(id + "-health"), command, workingDirectory,
                Map.of(
                        "PATH", String.join(File.pathSeparator, pathEntries),
                        "HOME", workingDirectory.toString(),
                        "TMPDIR", workingDirectory.toString(),
                        "LANG", "C"),
                Duration.ofSeconds(30), new ResourceRequest(ResourceClass.LIGHT, 1, 256),
                Set.of(), RedactionPolicy.NONE);
    }

    private ToolInstallationHealth unavailable(String id, Path executable, String code, String detail) {
        return health(id, "UNAVAILABLE", executable, code, detail);
    }

    private ToolInstallationHealth incompatible(String id, Path executable, String code, String detail) {
        return health(id, "INCOMPATIBLE", executable, code, detail);
    }

    private ToolInstallationHealth health(String id, String status, Path executable, String code, String detail) {
        return new ToolInstallationHealth(id, status, "", executable, "", code,
                detail == null ? "" : detail, clock.instant());
    }

    private String sha256(Path file) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }
}
