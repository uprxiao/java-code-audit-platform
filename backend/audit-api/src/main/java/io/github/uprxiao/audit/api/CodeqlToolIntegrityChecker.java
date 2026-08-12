package io.github.uprxiao.audit.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import java.io.IOException;
import java.io.InputStream;
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

/** Controlled local-only CodeQL probe. It never downloads or redistributes the CLI. */
final class CodeqlToolIntegrityChecker {

    private static final String MANIFEST = "audit/tools/codeql-local.yaml";

    private final AuditRuntimePaths paths;
    private final LocalProcessExecutionBackend processes;
    private final ObjectMapper json;
    private final Clock clock;

    CodeqlToolIntegrityChecker(
            AuditRuntimePaths paths,
            LocalProcessExecutionBackend processes,
            ObjectMapper json,
            Clock clock) {
        this.paths = paths;
        this.processes = processes;
        this.json = json;
        this.clock = clock;
    }

    ToolInstallationHealth check() throws IOException, InterruptedException {
        Path executable = paths.codeqlExecutable();
        if (!Files.isRegularFile(executable) || !Files.isExecutable(executable)) {
            return health("UNAVAILABLE", "", executable, "", "EXECUTABLE_NOT_FOUND", executable.toString());
        }
        if (!Files.isRegularFile(paths.codeqlQuerySuite())) {
            return health("UNAVAILABLE", "", executable, "", "CODEQL_QUERY_SUITE_UNAVAILABLE",
                    paths.codeqlQuerySuite().toString());
        }
        JsonNode manifest = manifest();
        String expectedVersion = manifest.path("cliVersion").asText();
        Path probe = Files.createDirectories(paths.dataRoot().resolve("health/probes/codeql"));
        ExecutionResult execution = processes.execute(new ExecutionSpec(
                new EngineId("codeql-health"),
                List.of(executable.toString(), "version", "--format=json"),
                probe,
                Map.of("PATH", executable.getParent().toString(), "HOME", probe.toString(), "LANG", "C"),
                Duration.ofSeconds(30), new ResourceRequest(ResourceClass.LIGHT, 1, 256),
                Set.of(), RedactionPolicy.NONE), CancellationToken.NONE);
        if (execution.status() != ExecutionResult.Status.SUCCEEDED) {
            return health("UNAVAILABLE", "", executable, "", "VERSION_COMMAND_FAILED", execution.message());
        }
        JsonNode version;
        try {
            version = json.readTree(execution.stdout().toFile());
        } catch (IOException exception) {
            return health("INCOMPATIBLE", "", executable, "", "VERSION_OUTPUT_INVALID", exception.getMessage());
        }
        String actualVersion = version.path("version").asText();
        if (!expectedVersion.equals(actualVersion)) {
            return health("INCOMPATIBLE", actualVersion, executable, "", "TOOL_VERSION_MISMATCH",
                    "expected=" + expectedVersion + ", actual=" + actualVersion);
        }
        String expectedPack = manifest.path("javaQueryPack").asText();
        String queryPackVersion = queryPackVersion(paths.codeqlQuerySuite());
        if (!expectedPack.endsWith("@" + queryPackVersion)) {
            return health("INCOMPATIBLE", actualVersion, executable, "", "CODEQL_QUERY_PACK_VERSION_MISMATCH",
                    "expected=" + expectedPack + ", actual=" + queryPackVersion);
        }
        return health("AVAILABLE", actualVersion, executable, sha256(executable), "",
                "CodeQL CLI is a controlled local installation and is never included in the release medium");
    }

    private JsonNode manifest() throws IOException {
        try (InputStream input = CodeqlToolIntegrityChecker.class.getClassLoader().getResourceAsStream(MANIFEST)) {
            if (input == null) {
                throw new IOException("missing CodeQL manifest: " + MANIFEST);
            }
            return new ObjectMapper(new YAMLFactory()).readTree(input);
        }
    }

    private String queryPackVersion(Path querySuite) throws IOException {
        Path current = querySuite.getParent();
        for (int depth = 0; depth < 5 && current != null; depth++, current = current.getParent()) {
            Path pack = current.resolve("qlpack.yml");
            if (Files.isRegularFile(pack)) {
                String version = new ObjectMapper(new YAMLFactory()).readTree(pack.toFile()).path("version").asText();
                if (!version.isBlank()) {
                    return version;
                }
            }
        }
        throw new IOException("cannot determine CodeQL Java query pack version");
    }

    private ToolInstallationHealth health(
            String status, String version, Path executable, String sha256, String code, String detail) {
        return new ToolInstallationHealth(
                "codeql", status, version, executable.toAbsolutePath().normalize(), sha256, code,
                detail == null ? "" : detail, clock.instant());
    }

    private String sha256(Path file) throws IOException {
        try (InputStream input = Files.newInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            for (int read; (read = input.read(buffer)) >= 0;) {
                if (read > 0) digest.update(buffer, 0, read);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }
}
