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
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Verifies Standard supply-chain tools and their non-bundled vulnerability data. */
final class StandardSupplyToolIntegrityChecker {

    private static final Duration TRIVY_STALE_AFTER = Duration.ofDays(7);
    private final AuditRuntimePaths paths;
    private final LocalProcessExecutionBackend processes;
    private final ObjectMapper json;
    private final Clock clock;
    private final String mavenExecutable;
    private final String pathEnvironment;
    private final List<ToolInstallationHealth> quickHealth;

    StandardSupplyToolIntegrityChecker(
            AuditRuntimePaths paths,
            LocalProcessExecutionBackend processes,
            ObjectMapper json,
            Clock clock,
            String mavenExecutable,
            String pathEnvironment,
            List<ToolInstallationHealth> quickHealth) {
        this.paths = paths;
        this.processes = processes;
        this.json = json;
        this.clock = clock;
        this.mavenExecutable = mavenExecutable;
        this.pathEnvironment = pathEnvironment;
        this.quickHealth = List.copyOf(quickHealth);
    }

    List<ToolInstallationHealth> checkAll() throws IOException, InterruptedException {
        return List.of(checkDependencyCheck(), checkOsv(), checkCycloneDx(), checkTrivyArtifact());
    }

    private ToolInstallationHealth checkDependencyCheck() throws IOException, InterruptedException {
        Path directory = paths.dependencyCheckToolDirectory();
        Path executable = paths.dependencyCheckExecutable();
        JsonNode metadata = metadata(directory.resolve("pack-metadata.json"), "dependency-check", executable);
        if (metadata == null) return unavailable("dependency-check", executable, "TOOL_METADATA_INVALID", "metadata unavailable");
        ToolInstallationHealth integrity = verifyFile("dependency-check", executable, directory,
                metadata.path("entrypoint").asText(), metadata.path("entrypointSha256").asText());
        if (!integrity.available()) return integrity;
        ToolInstallationHealth version = probeVersion("dependency-check", "12.2.2", executable,
                List.of(executable.toString(), "--version"), integrity.sha256());
        if (!version.available()) return version;
        Path data = paths.dependencyCheckData();
        boolean databasePresent;
        try (var files = Files.isDirectory(data) ? Files.list(data) : java.util.stream.Stream.<Path>empty()) {
            databasePresent = files.anyMatch(file -> file.getFileName().toString().startsWith("odc")
                    && file.getFileName().toString().contains(".mv.db") && nonEmpty(file));
        }
        if (!databasePresent) {
            return unavailable("dependency-check", executable, "VULNERABILITY_DATABASE_UNAVAILABLE",
                    "Dependency-Check database is not initialized");
        }
        if (Files.exists(data.resolve("ACCEPTANCE-ONLY.txt"))) {
            return unavailable("dependency-check", executable, "VULNERABILITY_DATABASE_NON_PRODUCTION",
                    "Dependency-Check acceptance-only data is prohibited for production scans");
        }
        Path provenanceFile = data.resolve("database-metadata.json");
        JsonNode provenance;
        try {
            provenance = json.readTree(provenanceFile.toFile());
        } catch (IOException exception) {
            return unavailable("dependency-check", executable, "VULNERABILITY_DATABASE_PROVENANCE_UNAVAILABLE",
                    "Production database metadata is missing or invalid");
        }
        String databaseFile = provenance.path("databaseFile").asText();
        Path databasePath = data.resolve(databaseFile).normalize();
        String expectedSha = provenance.path("databaseSha256").asText();
        String source = provenance.path("source").asText();
        if (provenance.path("schemaVersion").asInt() != 1
                || !"dependency-check-nvd".equals(provenance.path("id").asText())
                || !"production-full".equals(provenance.path("mode").asText())
                || provenance.path("productionUseProhibited").asBoolean(true)
                || !"12.2.2".equals(provenance.path("dependencyCheckVersion").asText())
                || !("nvd-api".equals(source) || "nvd-datafeed".equals(source))
                || !databaseFile.matches("odc[^/\\\\]*\\.mv\\.db")
                || !databasePath.startsWith(data.normalize()) || !nonEmpty(databasePath)
                || provenance.path("databaseSizeBytes").asLong(-1) != Files.size(databasePath)
                || expectedSha.length() != 64) {
            return unavailable("dependency-check", executable, "VULNERABILITY_DATABASE_PROVENANCE_INVALID",
                    "Production database metadata does not prove a complete Dependency-Check NVD update");
        }
        String actualSha = sha256(databasePath);
        if (!actualSha.equalsIgnoreCase(expectedSha)) {
            return unavailable("dependency-check", executable, "VULNERABILITY_DATABASE_SHA256_MISMATCH",
                    "Dependency-Check database does not match its production metadata");
        }
        Instant updatedAt;
        try {
            updatedAt = Instant.parse(provenance.path("updatedAt").asText());
        } catch (DateTimeParseException exception) {
            return unavailable("dependency-check", executable, "VULNERABILITY_DATABASE_PROVENANCE_INVALID",
                    "Production database updatedAt is missing or invalid");
        }
        boolean stale = updatedAt.plus(TRIVY_STALE_AFTER).isBefore(clock.instant());
        Map<String, Object> database = Map.of(
                "id", "dependency-check-nvd", "version", "h2", "source", source,
                "updatedAt", updatedAt.toString(), "stale", stale,
                "databaseSha256", actualSha, "productionUseProhibited", false);
        return stale
                ? degraded("dependency-check", "12.2.2", executable, version.sha256(),
                        "Dependency-Check vulnerability database is older than 7 days", database)
                : available("dependency-check", "12.2.2", executable, version.sha256(), "", database);
    }

    private ToolInstallationHealth checkOsv() throws IOException, InterruptedException {
        Path directory = paths.osvScannerToolDirectory();
        Path executable = paths.osvScannerExecutable();
        JsonNode metadata = metadata(directory.resolve("pack-metadata.json"), "osv-scanner", executable);
        if (metadata == null) return unavailable("osv-scanner", executable, "TOOL_METADATA_INVALID", "metadata unavailable");
        ToolInstallationHealth wrapper = verifyFile("osv-scanner", executable, directory,
                metadata.path("entrypoint").asText(), metadata.path("entrypointSha256").asText());
        if (!wrapper.available()) return wrapper;
        ToolInstallationHealth binary = verifyFile("osv-scanner", executable, directory,
                metadata.path("upstreamBinary").asText(), metadata.path("upstreamBinarySha256").asText());
        if (!binary.available()) return binary;
        return probeVersion("osv-scanner", "2.3.8", executable,
                List.of(executable.toString(), "--version"), wrapper.sha256());
    }

    private ToolInstallationHealth checkCycloneDx() throws IOException, InterruptedException {
        Path resolved = StandardAnalysisToolIntegrityChecker.resolveExecutable(mavenExecutable, pathEnvironment);
        Path executable = resolved == null ? Path.of(mavenExecutable).toAbsolutePath().normalize() : resolved;
        JsonNode metadata = metadata(paths.cycloneDxMetadata(), "cyclonedx", executable);
        if (metadata == null) return unavailable("cyclonedx", executable, "TOOL_METADATA_INVALID", "metadata unavailable");
        if (!"2.9.3".equals(metadata.path("version").asText())
                || !"org.cyclonedx:cyclonedx-maven-plugin:2.9.3".equals(metadata.path("coordinate").asText())
                || metadata.path("artifactSha256").asText().length() != 64) {
            return incompatible("cyclonedx", executable, "TOOL_METADATA_MISMATCH",
                    "CycloneDX coordinate or artifact checksum is not pinned");
        }
        if (resolved == null) return unavailable("cyclonedx", executable, "EXECUTABLE_NOT_FOUND", mavenExecutable);
        ToolInstallationHealth maven = probeVersion("cyclonedx", "Apache Maven", resolved,
                List.of(resolved.toString(), "--version"), sha256(resolved));
        if (!maven.available()) return maven;
        String output = maven.detail();
        if (!supportsMavenAndJava(output)) {
            return incompatible("cyclonedx", resolved, "MAVEN_RUNTIME_INCOMPATIBLE", output);
        }
        return available("cyclonedx", "2.9.3", resolved, sha256(resolved),
                output + System.lineSeparator()
                        + "Pinned Maven plugin org.cyclonedx:cyclonedx-maven-plugin:2.9.3; artifact SHA-256 "
                        + metadata.path("artifactSha256").asText());
    }

    private ToolInstallationHealth checkTrivyArtifact() throws IOException {
        ToolInstallationHealth quick = quickHealth.stream()
                .filter(tool -> "trivy-repository".equals(tool.id())).findFirst().orElse(null);
        Path executable = paths.trivyExecutable();
        if (quick == null || !quick.available()) {
            return unavailable("trivy-artifact", executable, "TOOL_UNAVAILABLE",
                    quick == null ? "Trivy Quick health is missing" : quick.reasonCode());
        }
        DatabaseHealth database = trivyDatabase();
        if (!database.available()) {
            return unavailable("trivy-artifact", executable, "VULNERABILITY_DATABASE_UNAVAILABLE", database.detail());
        }
        return database.stale()
                ? degraded("trivy-artifact", quick.version(), executable, quick.sha256(), database.detail(),
                        database.metadata())
                : available("trivy-artifact", quick.version(), executable, quick.sha256(), database.detail(),
                        database.metadata());
    }

    private DatabaseHealth trivyDatabase() {
        Path root = paths.vulnerabilityTrivyCache();
        Path metadata = root.resolve("db/metadata.json");
        Path database = root.resolve("db/trivy.db");
        Path javaMetadata = root.resolve("java-db/metadata.json");
        Path javaDatabase = root.resolve("java-db/trivy-java.db");
        if (!nonEmpty(metadata) || !nonEmpty(database) || !nonEmpty(javaMetadata) || !nonEmpty(javaDatabase)) {
            return new DatabaseHealth(false, false,
                    "Trivy vulnerability and Java databases are both required", Map.of());
        }
        try {
            Instant updated = Instant.parse(json.readTree(metadata.toFile()).path("UpdatedAt").asText());
            Instant javaUpdated = Instant.parse(json.readTree(javaMetadata.toFile()).path("UpdatedAt").asText());
            boolean stale = updated.plus(TRIVY_STALE_AFTER).isBefore(clock.instant())
                    || javaUpdated.plus(TRIVY_STALE_AFTER).isBefore(clock.instant());
            Map<String, Object> value = Map.of(
                    "id", "trivy-vulnerability-and-java",
                    "version", json.readTree(metadata.toFile()).path("Version").asText("") + "/"
                            + json.readTree(javaMetadata.toFile()).path("Version").asText(""),
                    "updatedAt", (updated.isBefore(javaUpdated) ? updated : javaUpdated).toString(),
                    "vulnerabilityUpdatedAt", updated.toString(),
                    "javaUpdatedAt", javaUpdated.toString(),
                    "stale", stale);
            return new DatabaseHealth(true, stale, "vulnerabilityUpdatedAt=" + updated
                    + ", javaUpdatedAt=" + javaUpdated + (stale ? ", stale=true" : ""), value);
        } catch (IOException | DateTimeParseException exception) {
            return new DatabaseHealth(false, false, "Trivy database metadata is invalid", Map.of());
        }
    }

    private JsonNode metadata(Path file, String expectedId, Path executable) throws IOException {
        if (!Files.isRegularFile(file)) return null;
        JsonNode value;
        try {
            value = json.readTree(file.toFile());
        } catch (IOException exception) {
            return null;
        }
        return expectedId.equals(value.path("id").asText()) ? value : null;
    }

    private ToolInstallationHealth verifyFile(
            String id, Path executable, Path directory, String relative, String expectedSha) throws IOException {
        Path entrypoint = directory.resolve(relative).normalize();
        if (relative.isBlank() || !entrypoint.startsWith(directory.normalize()) || !Files.isRegularFile(entrypoint)
                || (entrypoint.equals(executable) && !Files.isExecutable(entrypoint))) {
            return unavailable(id, executable, "EXECUTABLE_NOT_FOUND", entrypoint.toString());
        }
        String actual = sha256(entrypoint);
        if (expectedSha.isBlank() || !actual.equalsIgnoreCase(expectedSha)) {
            return incompatible(id, executable, "TOOL_SHA256_MISMATCH", "actual=" + actual);
        }
        return available(id, "", executable, actual, "");
    }

    private ToolInstallationHealth probeVersion(
            String id, String expected, Path executable, List<String> command, String sha)
            throws IOException, InterruptedException {
        if (!Files.isRegularFile(executable) || !Files.isExecutable(executable)) {
            return unavailable(id, executable, "EXECUTABLE_NOT_FOUND", executable.toString());
        }
        Path directory = Files.createDirectories(paths.dataRoot().resolve("health/probes").resolve(id));
        ExecutionResult execution = processes.execute(new ExecutionSpec(
                new EngineId(id + "-health"), command, directory,
                Map.of("PATH", executable.getParent() + File.pathSeparator + pathEnvironment,
                        "JAVA_HOME", System.getProperty("java.home"), "HOME", directory.toString(),
                        "TMPDIR", directory.toString(), "LANG", "C"),
                Duration.ofSeconds(30), new ResourceRequest(ResourceClass.LIGHT, 1, 256),
                Set.of(), RedactionPolicy.NONE), CancellationToken.NONE);
        if (execution.status() != ExecutionResult.Status.SUCCEEDED) {
            return unavailable(id, executable, "VERSION_COMMAND_FAILED", execution.message());
        }
        String output = Files.readString(execution.stdout()) + "\n" + Files.readString(execution.stderr());
        if (!output.toLowerCase(Locale.ROOT).contains(expected.toLowerCase(Locale.ROOT))) {
            return incompatible(id, executable, "TOOL_VERSION_MISMATCH", output.strip());
        }
        String version = switch (id) {
            case "dependency-check" -> "12.2.2";
            case "osv-scanner" -> "2.3.8";
            default -> expected;
        };
        return available(id, version, executable, sha, output.strip());
    }

    private boolean supportsMavenAndJava(String output) {
        java.util.regex.Matcher maven = java.util.regex.Pattern.compile("(?m)^Apache Maven (\\d+)\\.(\\d+).*$")
                .matcher(output);
        java.util.regex.Matcher javaVersion = java.util.regex.Pattern.compile("(?m)^Java version: (\\d+).*$")
                .matcher(output);
        if (!maven.find() || !javaVersion.find()) return false;
        int major = Integer.parseInt(maven.group(1));
        int minor = Integer.parseInt(maven.group(2));
        return (major > 3 || (major == 3 && minor >= 9)) && Integer.parseInt(javaVersion.group(1)) == 17;
    }

    private boolean nonEmpty(Path file) {
        try { return Files.isRegularFile(file) && Files.size(file) > 0; }
        catch (IOException ignored) { return false; }
    }

    private ToolInstallationHealth available(
            String id, String version, Path executable, String sha, String detail) {
        return available(id, version, executable, sha, detail, Map.of());
    }

    private ToolInstallationHealth available(
            String id, String version, Path executable, String sha, String detail, Map<String, Object> database) {
        return new ToolInstallationHealth(id, "AVAILABLE", version, executable.toAbsolutePath().normalize(),
                sha, "", detail, clock.instant(), database);
    }

    private ToolInstallationHealth degraded(
            String id, String version, Path executable, String sha, String detail, Map<String, Object> database) {
        return new ToolInstallationHealth(id, "DEGRADED", version, executable.toAbsolutePath().normalize(),
                sha, "VULNERABILITY_DATABASE_STALE", detail, clock.instant(), database);
    }

    private ToolInstallationHealth unavailable(String id, Path executable, String code, String detail) {
        return health(id, "UNAVAILABLE", executable, code, detail);
    }

    private ToolInstallationHealth incompatible(String id, Path executable, String code, String detail) {
        return health(id, "INCOMPATIBLE", executable, code, detail);
    }

    private ToolInstallationHealth health(String id, String status, Path executable, String code, String detail) {
        return new ToolInstallationHealth(id, status, "", executable.toAbsolutePath().normalize(), "", code,
                detail == null ? "" : detail, clock.instant());
    }

    private String sha256(Path file) throws IOException {
        try (var input = Files.newInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            for (int read; (read = input.read(buffer)) >= 0;) if (read > 0) digest.update(buffer, 0, read);
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    private record DatabaseHealth(
            boolean available, boolean stale, String detail, Map<String, Object> metadata) { }
}
