package io.github.uprxiao.audit.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.storage.AtomicFileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class StartupPrerequisiteChecker {

    private static final Pattern MAVEN_VERSION = Pattern.compile("Apache Maven (\\d+)\\.(\\d+)(?:\\.(\\d+))?.*");
    private static final Pattern MAVEN_JAVA = Pattern.compile("Java version: (\\d+)(?:\\.[^, ]*)?.*");
    private static final Pattern GLIBC_VERSION = Pattern.compile(".*(?:GLIBC|GNU libc|GNU C Library)[^0-9]*(\\d+)\\.(\\d+).*",
            Pattern.CASE_INSENSITIVE);

    private final AuditRuntimePaths paths;
    private final LocalProcessExecutionBackend processes;
    private final AtomicFileWriter files;
    private final ObjectMapper json;
    private final Clock clock;
    private final String mavenExecutable;
    private final long minimumDiskBytes;
    private final List<ToolInstallationHealth> tools;

    StartupPrerequisiteChecker(
            AuditRuntimePaths paths,
            LocalProcessExecutionBackend processes,
            AtomicFileWriter files,
            ObjectMapper json,
            Clock clock,
            String mavenExecutable,
            long minimumDiskBytes,
            ToolInstallationHealth semgrep) {
        this(paths, processes, files, json, clock, mavenExecutable, minimumDiskBytes, List.of(semgrep));
    }

    StartupPrerequisiteChecker(
            AuditRuntimePaths paths,
            LocalProcessExecutionBackend processes,
            AtomicFileWriter files,
            ObjectMapper json,
            Clock clock,
            String mavenExecutable,
            long minimumDiskBytes,
            List<ToolInstallationHealth> tools) {
        this.paths = paths;
        this.processes = processes;
        this.files = files;
        this.json = json;
        this.clock = clock;
        this.mavenExecutable = mavenExecutable;
        this.minimumDiskBytes = minimumDiskBytes;
        this.tools = List.copyOf(tools);
    }

    StartupHealthSnapshot checkAndPersist() throws IOException, InterruptedException {
        if (Runtime.version().feature() != 17) {
            throw new IllegalStateException("Java Code Audit Platform V1 requires runtime JDK 17");
        }
        if (minimumDiskBytes < 1) {
            throw new IllegalArgumentException("minimum free disk bytes must be positive");
        }
        Files.createDirectories(paths.dataRoot());
        if (!Files.isWritable(paths.dataRoot())) {
            throw new IllegalStateException("data directory is not writable: " + paths.dataRoot());
        }
        FileStore store = Files.getFileStore(paths.dataRoot());
        long usableDiskBytes = store.getUsableSpace();
        if (usableDiskBytes < minimumDiskBytes) {
            throw new IllegalStateException("usable disk space is below the configured startup minimum: "
                    + usableDiskBytes + " < " + minimumDiskBytes);
        }

        Path probe = paths.dataRoot().resolve("health/probes/maven");
        Files.createDirectories(probe);
        ExecutionResult result = processes.execute(mavenVersionSpec(probe), CancellationToken.NONE);
        if (result.status() != ExecutionResult.Status.SUCCEEDED) {
            throw new IllegalStateException("system Maven version check failed: " + result.message());
        }
        String output = Files.readString(result.stdout(), StandardCharsets.UTF_8) + "\n"
                + Files.readString(result.stderr(), StandardCharsets.UTF_8);
        String mavenVersion = extractMavenVersion(output);
        String mavenJavaVersion = extractMavenJavaVersion(output);
        String runtimeLibc = runtimeLibc(paths.dataRoot().resolve("health/probes/libc"));
        StartupHealthSnapshot snapshot = new StartupHealthSnapshot(
                tools.stream().allMatch(ToolInstallationHealth::available) ? "UP" : "DEGRADED",
                System.getProperty("os.name", "unknown"),
                System.getProperty("os.arch", "unknown"),
                runtimeLibc,
                System.getProperty("java.version", "unknown"),
                mavenVersion,
                mavenJavaVersion,
                tools,
                usableDiskBytes,
                minimumDiskBytes,
                clock.instant());
        files.write(paths.dataRoot().resolve("health/startup.json"), json.writeValueAsBytes(snapshot));
        return snapshot;
    }

    private String runtimeLibc(Path probe) throws IOException, InterruptedException {
        String operatingSystem = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (!operatingSystem.contains("linux")) {
            return "not-applicable";
        }
        Path ldd = List.of(Path.of("/usr/bin/ldd"), Path.of("/bin/ldd")).stream()
                .filter(Files::isRegularFile).filter(Files::isExecutable).findFirst()
                .orElseThrow(() -> new IllegalStateException("Linux V1 requires an executable ldd for glibc verification"));
        Files.createDirectories(probe);
        ExecutionSpec specification = new ExecutionSpec(
                new EngineId("glibc-health"), List.of(ldd.toString(), "--version"), probe,
                Map.of("PATH", "/usr/bin:/bin", "LANG", "C", "LC_ALL", "C"), Duration.ofSeconds(10),
                new ResourceRequest(ResourceClass.LIGHT, 1, 64), Set.of(), RedactionPolicy.NONE);
        ExecutionResult result = processes.execute(specification, CancellationToken.NONE);
        if (result.status() != ExecutionResult.Status.SUCCEEDED) {
            throw new IllegalStateException("glibc version check failed: " + result.message());
        }
        String output = Files.readString(result.stdout(), StandardCharsets.UTF_8) + "\n"
                + Files.readString(result.stderr(), StandardCharsets.UTF_8);
        for (String line : output.lines().toList()) {
            Matcher matcher = GLIBC_VERSION.matcher(line.trim());
            if (!matcher.matches()) {
                continue;
            }
            int major = Integer.parseInt(matcher.group(1));
            int minor = Integer.parseInt(matcher.group(2));
            if (major < 2 || (major == 2 && minor < 34)) {
                throw new IllegalStateException("glibc 2.34 or newer is required, found " + major + "." + minor);
            }
            return "glibc " + major + "." + minor;
        }
        throw new IllegalStateException("Linux V1 requires glibc 2.34+; ldd output was not recognized");
    }

    private ExecutionSpec mavenVersionSpec(Path probe) {
        String javaHome = System.getProperty("java.home");
        String path = System.getenv().getOrDefault("PATH", "/usr/bin:/bin");
        return new ExecutionSpec(
                new EngineId("maven-health"),
                List.of(mavenExecutable, "--version"),
                probe,
                Map.of("JAVA_HOME", javaHome, "PATH", path, "LANG", "C"),
                Duration.ofSeconds(15),
                new ResourceRequest(ResourceClass.LIGHT, 1, 128),
                Set.of(),
                RedactionPolicy.NONE);
    }

    private String extractMavenVersion(String output) {
        for (String line : output.lines().toList()) {
            Matcher matcher = MAVEN_VERSION.matcher(line.trim());
            if (matcher.matches()) {
                int major = Integer.parseInt(matcher.group(1));
                int minor = Integer.parseInt(matcher.group(2));
                if (major < 3 || (major == 3 && minor < 9)) {
                    throw new IllegalStateException("Maven 3.9 or newer is required, found " + line.trim());
                }
                return matcher.group(1) + "." + matcher.group(2)
                        + (matcher.group(3) == null ? "" : "." + matcher.group(3));
            }
        }
        throw new IllegalStateException("cannot determine Maven version");
    }

    private String extractMavenJavaVersion(String output) {
        for (String line : output.lines().toList()) {
            Matcher matcher = MAVEN_JAVA.matcher(line.trim());
            if (matcher.matches()) {
                if (Integer.parseInt(matcher.group(1)) != 17) {
                    throw new IllegalStateException("Maven must use JDK 17, found " + line.trim());
                }
                return matcher.group(1);
            }
        }
        throw new IllegalStateException("cannot determine the JDK used by Maven");
    }
}
