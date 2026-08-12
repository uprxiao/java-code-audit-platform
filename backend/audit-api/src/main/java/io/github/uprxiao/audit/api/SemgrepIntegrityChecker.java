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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class SemgrepIntegrityChecker {

    private final AuditRuntimePaths paths;
    private final LocalProcessExecutionBackend processes;
    private final ObjectMapper json;
    private final Clock clock;
    private final String expectedVersion;

    SemgrepIntegrityChecker(
            AuditRuntimePaths paths,
            LocalProcessExecutionBackend processes,
            ObjectMapper json,
            Clock clock,
            String expectedVersion) {
        this.paths = paths;
        this.processes = processes;
        this.json = json;
        this.clock = clock;
        this.expectedVersion = expectedVersion;
    }

    ToolInstallationHealth check() throws IOException, InterruptedException {
        Path executable = paths.semgrepExecutable();
        if (!Files.isRegularFile(executable) || !Files.isExecutable(executable)) {
            return unhealthy("UNAVAILABLE", executable, "EXECUTABLE_NOT_FOUND", executable.toString());
        }
        Path metadata = executable.getParent().getParent().getParent().resolve("pack-metadata.json");
        if (!Files.isRegularFile(metadata)) {
            return unhealthy("INCOMPATIBLE", executable, "TOOL_METADATA_MISSING", metadata.toString());
        }
        JsonNode manifest;
        try {
            manifest = json.readTree(metadata.toFile());
        } catch (IOException exception) {
            return unhealthy("INCOMPATIBLE", executable, "TOOL_METADATA_INVALID", exception.getMessage());
        }
        String manifestVersion = manifest.path("semgrepVersion").asText();
        String expectedSha256 = manifest.path("entrypointSha256").asText();
        String actualSha256 = sha256(executable);
        if (!expectedVersion.equals(manifestVersion)) {
            return unhealthy("INCOMPATIBLE", executable, "TOOL_VERSION_MISMATCH",
                    "metadata=" + manifestVersion + ", expected=" + expectedVersion);
        }
        if (expectedSha256.isBlank() || !actualSha256.equalsIgnoreCase(expectedSha256)) {
            return unhealthy("INCOMPATIBLE", executable, "TOOL_SHA256_MISMATCH",
                    "actual=" + actualSha256);
        }

        Path probeDirectory = paths.dataRoot().resolve("health/probes/semgrep");
        Files.createDirectories(probeDirectory);
        ExecutionResult execution = processes.execute(versionSpec(executable, probeDirectory), CancellationToken.NONE);
        if (execution.status() != ExecutionResult.Status.SUCCEEDED) {
            return unhealthy("UNAVAILABLE", executable, "VERSION_COMMAND_FAILED", execution.message());
        }
        String output = Files.readString(execution.stdout()) + "\n" + Files.readString(execution.stderr());
        boolean versionMatches = output.lines().map(String::trim).anyMatch(expectedVersion::equals);
        if (!versionMatches) {
            return unhealthy("INCOMPATIBLE", executable, "TOOL_VERSION_MISMATCH", output.strip());
        }
        return new ToolInstallationHealth(
                "semgrep", "AVAILABLE", expectedVersion, executable, actualSha256, "", "", clock.instant());
    }

    private ExecutionSpec versionSpec(Path executable, Path workingDirectory) {
        Path toolBin = executable.getParent();
        String path = toolBin + java.io.File.pathSeparator + "/usr/bin" + java.io.File.pathSeparator + "/bin";
        return new ExecutionSpec(
                new EngineId("semgrep-health"),
                List.of(executable.toString(), "--version"),
                workingDirectory,
                Map.of(
                        "PATH", path,
                        "HOME", workingDirectory.toString(),
                        "TMPDIR", workingDirectory.toString()),
                Duration.ofSeconds(30),
                new ResourceRequest(ResourceClass.LIGHT, 1, 128),
                Set.of(),
                RedactionPolicy.NONE);
    }

    private ToolInstallationHealth unhealthy(String status, Path executable, String reasonCode, String detail) {
        return new ToolInstallationHealth(
                "semgrep", status, "", executable, "", reasonCode,
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
