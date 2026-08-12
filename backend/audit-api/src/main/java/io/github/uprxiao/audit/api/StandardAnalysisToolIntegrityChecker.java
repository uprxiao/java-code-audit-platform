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
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Validates the four Standard analysis engines against the committed immutable metadata. */
final class StandardAnalysisToolIntegrityChecker {

    private static final String MANIFEST = "audit/tools/standard-analysis/tools.yaml";
    private static final Pattern MAVEN_VERSION = Pattern.compile("Apache Maven (\\d+)\\.(\\d+)(?:\\.(\\d+))?.*");
    private static final Pattern MAVEN_JAVA = Pattern.compile("Java version: (\\d+)(?:\\.[^, ]*)?.*");

    private final AuditRuntimePaths paths;
    private final LocalProcessExecutionBackend processes;
    private final Clock clock;
    private final String mavenExecutable;
    private final String pathEnvironment;
    private final Map<String, JsonNode> tools;

    StandardAnalysisToolIntegrityChecker(
            AuditRuntimePaths paths,
            LocalProcessExecutionBackend processes,
            Clock clock,
            String mavenExecutable,
            String pathEnvironment) throws IOException {
        this.paths = paths;
        this.processes = processes;
        this.clock = clock;
        this.mavenExecutable = mavenExecutable;
        this.pathEnvironment = pathEnvironment;
        this.tools = loadManifest();
    }

    List<ToolInstallationHealth> checkAll() throws IOException, InterruptedException {
        Path java = paths.javaExecutable();
        ToolInstallationHealth spotbugs = checkSpotBugs(java);
        ToolInstallationHealth findsecbugs = checkFindSecBugs(java);
        MavenProbe maven = probeMaven();
        return List.of(
                spotbugs,
                findsecbugs,
                mavenHealth("maven-dependency-analysis", maven),
                mavenHealth("maven-enforcer", maven));
    }

    private ToolInstallationHealth checkSpotBugs(Path java) throws IOException, InterruptedException {
        JsonNode metadata = requireMetadata("spotbugs");
        Path entrypoint = paths.spotbugsHome().resolve("lib/spotbugs.jar");
        ToolInstallationHealth integrity = verifyEntrypoint("spotbugs", java, entrypoint, metadata);
        if (!integrity.available()) {
            return integrity;
        }
        Path probe = probeDirectory("spotbugs");
        ExecutionResult execution = processes.execute(new ExecutionSpec(
                new EngineId("spotbugs-health"),
                List.of(java.toString(), "-cp", paths.spotbugsHome().resolve("lib/*").toString(),
                        "edu.umd.cs.findbugs.LaunchAppropriateUI", "-textui", "-version"),
                probe, isolatedEnvironment(probe, java), Duration.ofSeconds(30),
                new ResourceRequest(ResourceClass.LIGHT, 1, 256), Set.of(), RedactionPolicy.NONE),
                CancellationToken.NONE);
        if (execution.status() != ExecutionResult.Status.SUCCEEDED) {
            return unavailable("spotbugs", java, "VERSION_COMMAND_FAILED", execution.message());
        }
        String output = Files.readString(execution.stdout()) + "\n" + Files.readString(execution.stderr());
        String version = metadata.path("version").asText();
        if (!output.contains(version)) {
            return incompatible("spotbugs", java, "TOOL_VERSION_MISMATCH", output.strip());
        }
        return available("spotbugs", version, java, integrity.sha256(), "");
    }

    private ToolInstallationHealth checkFindSecBugs(Path java) throws IOException {
        JsonNode metadata = requireMetadata("findsecbugs");
        Path entrypoint = paths.findSecBugsPlugin();
        ToolInstallationHealth integrity = verifyEntrypoint("findsecbugs", java, entrypoint, metadata);
        if (!integrity.available()) {
            return integrity;
        }
        return available("findsecbugs", metadata.path("version").asText(), java, integrity.sha256(),
                "FindSecBugs plugin identity is pinned by its verified JAR SHA-256");
    }

    private ToolInstallationHealth verifyEntrypoint(
            String id, Path executable, Path entrypoint, JsonNode metadata) throws IOException {
        if (!Files.isRegularFile(executable) || !Files.isExecutable(executable)) {
            return unavailable(id, executable, "EXECUTABLE_NOT_FOUND", executable.toString());
        }
        if (!Files.isRegularFile(entrypoint)) {
            return unavailable(id, executable, "TOOL_ENTRYPOINT_MISSING", entrypoint.toString());
        }
        String actual = sha256(entrypoint);
        String expected = metadata.path("entrypointSha256").asText();
        if (expected.isBlank() || !expected.equalsIgnoreCase(actual)) {
            return incompatible(id, executable, "TOOL_SHA256_MISMATCH", "actual=" + actual);
        }
        return available(id, metadata.path("version").asText(), executable, actual, "");
    }

    private MavenProbe probeMaven() throws IOException, InterruptedException {
        Path resolved = resolveExecutable(mavenExecutable, pathEnvironment);
        if (resolved == null) {
            return new MavenProbe(null, false, "EXECUTABLE_NOT_FOUND", mavenExecutable, "");
        }
        Path probe = probeDirectory("maven-standard");
        ExecutionResult execution = processes.execute(new ExecutionSpec(
                new EngineId("maven-standard-health"), List.of(resolved.toString(), "--version"), probe,
                Map.of(
                        "PATH", pathEnvironment,
                        "JAVA_HOME", System.getProperty("java.home"),
                        "HOME", probe.toString(),
                        "LANG", "C"),
                Duration.ofSeconds(15), new ResourceRequest(ResourceClass.LIGHT, 1, 128),
                Set.of(), RedactionPolicy.NONE), CancellationToken.NONE);
        if (execution.status() != ExecutionResult.Status.SUCCEEDED) {
            return new MavenProbe(resolved, false, "VERSION_COMMAND_FAILED", execution.message(), sha256(resolved));
        }
        String output = Files.readString(execution.stdout()) + "\n" + Files.readString(execution.stderr());
        Matcher version = output.lines().map(String::trim).map(MAVEN_VERSION::matcher)
                .filter(Matcher::matches).findFirst().orElse(null);
        Matcher java = output.lines().map(String::trim).map(MAVEN_JAVA::matcher)
                .filter(Matcher::matches).findFirst().orElse(null);
        if (version == null || Integer.parseInt(version.group(1)) < 3
                || (Integer.parseInt(version.group(1)) == 3 && Integer.parseInt(version.group(2)) < 9)) {
            return new MavenProbe(resolved, false, "MAVEN_VERSION_INCOMPATIBLE", output.strip(), sha256(resolved));
        }
        if (java == null || Integer.parseInt(java.group(1)) != 17) {
            return new MavenProbe(resolved, false, "MAVEN_JAVA_INCOMPATIBLE", output.strip(), sha256(resolved));
        }
        return new MavenProbe(resolved, true, "", "", sha256(resolved));
    }

    private ToolInstallationHealth mavenHealth(String id, MavenProbe probe) {
        JsonNode metadata = requireMetadata(id);
        String version = metadata.path("version").asText();
        Path executable = probe.executable() == null ? Path.of(mavenExecutable) : probe.executable();
        if (!probe.available()) {
            return unavailable(id, executable, probe.reasonCode(), probe.detail());
        }
        return available(id, version, executable, probe.sha256(),
                "Pinned Maven plugin coordinate " + metadata.path("coordinate").asText());
    }

    private Map<String, JsonNode> loadManifest() throws IOException {
        try (InputStream input = StandardAnalysisToolIntegrityChecker.class.getClassLoader()
                .getResourceAsStream(MANIFEST)) {
            if (input == null) {
                throw new IOException("missing Standard tool manifest: " + MANIFEST);
            }
            JsonNode root = new ObjectMapper(new YAMLFactory()).readTree(input);
            Map<String, JsonNode> result = new LinkedHashMap<>();
            root.path("tools").forEach(tool -> result.put(tool.path("id").asText(), tool));
            return Map.copyOf(result);
        }
    }

    private JsonNode requireMetadata(String id) {
        JsonNode metadata = tools.get(id);
        if (metadata == null) {
            throw new IllegalStateException("missing tool metadata for " + id);
        }
        return metadata;
    }

    private Path probeDirectory(String id) throws IOException {
        return Files.createDirectories(paths.dataRoot().resolve("health/probes").resolve(id));
    }

    private Map<String, String> isolatedEnvironment(Path home, Path executable) {
        String executableDirectory = executable.getParent() == null ? "" : executable.getParent().toString();
        return Map.of(
                "PATH", executableDirectory + File.pathSeparator + "/usr/bin" + File.pathSeparator + "/bin",
                "JAVA_HOME", System.getProperty("java.home"),
                "HOME", home.toString(),
                "TMPDIR", home.toString(),
                "LANG", "C");
    }

    static Path resolveExecutable(String executable, String pathEnvironment) {
        Path configured = Path.of(executable);
        if (configured.isAbsolute()) {
            return Files.isRegularFile(configured) && Files.isExecutable(configured)
                    ? configured.toAbsolutePath().normalize() : null;
        }
        if (configured.getNameCount() != 1) {
            return null;
        }
        for (String entry : pathEnvironment.split(Pattern.quote(File.pathSeparator))) {
            if (entry.isBlank()) {
                continue;
            }
            Path candidate = Path.of(entry).resolve(executable).toAbsolutePath().normalize();
            if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private ToolInstallationHealth available(
            String id, String version, Path executable, String sha256, String detail) {
        return new ToolInstallationHealth(
                id, "AVAILABLE", version, executable.toAbsolutePath().normalize(), sha256, "", detail, clock.instant());
    }

    private ToolInstallationHealth unavailable(String id, Path executable, String code, String detail) {
        return health(id, "UNAVAILABLE", executable, code, detail);
    }

    private ToolInstallationHealth incompatible(String id, Path executable, String code, String detail) {
        return health(id, "INCOMPATIBLE", executable, code, detail);
    }

    private ToolInstallationHealth health(String id, String status, Path executable, String code, String detail) {
        return new ToolInstallationHealth(
                id, status, "", executable.toAbsolutePath().normalize(), "", code,
                detail == null ? "" : detail, clock.instant());
    }

    private String sha256(Path file) throws IOException {
        try (InputStream input = Files.newInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            for (int read; (read = input.read(buffer)) >= 0;) {
                if (read > 0) {
                    digest.update(buffer, 0, read);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by Java 17", exception);
        }
    }

    private record MavenProbe(Path executable, boolean available, String reasonCode, String detail, String sha256) {
    }
}
