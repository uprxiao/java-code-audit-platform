package io.github.uprxiao.audit.adapter.testing;

import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.SourceType;
import io.github.uprxiao.audit.intake.MavenModule;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.intake.ProjectManifest;
import io.github.uprxiao.audit.intake.SourceDescriptor;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class AdapterTestFixtures {

    private AdapterTestFixtures() {
    }

    public static Path copyProject(Class<?> owner, String fixtureRoot, Path destination) throws Exception {
        Path resource = Path.of(owner.getResource(fixtureRoot + "/project").toURI());
        try (var paths = Files.walk(resource)) {
            for (Path source : paths.toList()) {
                Path target = destination.resolve(resource.relativize(source).toString());
                if (Files.isDirectory(source)) Files.createDirectories(target); else Files.copy(source, target);
            }
        }
        return destination.toAbsolutePath().normalize();
    }

    public static Path copyReport(Class<?> owner, String fixtureRoot, String name, Path destination, Path projectRoot)
            throws Exception {
        try (InputStream input = owner.getResourceAsStream(fixtureRoot + "/" + name)) {
            if (input == null) throw new IllegalArgumentException("missing fixture " + fixtureRoot + "/" + name);
            String content = new String(input.readAllBytes(), StandardCharsets.UTF_8)
                    .replace("@PROJECT_ROOT@", projectRoot.toString().replace("\\", "\\\\"));
            Files.writeString(destination, content);
        }
        return destination;
    }

    public static ProjectContext project(Path root, String artifactId) {
        SourceDescriptor source = new SourceDescriptor(SourceType.ZIP, "fixture", "fixture.zip", "", "sha256");
        ProjectManifest manifest = new ProjectManifest(1, ".", "pom.xml", 17, "jar",
                java.util.List.of(new MavenModule(".", artifactId, "jar")), source,
                Set.of(ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP), java.util.List.of());
        return new ProjectContext(root, manifest);
    }

    public static ScanContext scan(ProjectContext project, Path output) {
        return new ScanContext(UUID.randomUUID(), ScanProfile.QUICK, project, output, null, null);
    }

    public static ToolContext tools(EngineId id, Path executable, String version) {
        return new ToolContext(executable.getParent(), Map.of(id,
                new ToolContext.ToolInstallation(executable, version, true)));
    }

    public static RawArtifactSet artifacts(EngineId id, Path report, Path output) throws Exception {
        return new RawArtifactSet(id, Map.of("report", report), execution(output, ExecutionResult.Status.SUCCEEDED, 0));
    }

    public static ExecutionResult execution(Path output, ExecutionResult.Status status, Integer exitCode) throws Exception {
        Files.createDirectories(output);
        Path stdout = output.resolve("stdout.log");
        Path stderr = output.resolve("stderr.log");
        if (!Files.exists(stdout)) Files.writeString(stdout, "");
        if (!Files.exists(stderr)) Files.writeString(stderr, "");
        Instant started = Instant.parse("2026-08-12T00:00:00Z");
        return new ExecutionResult(status, exitCode, started, started.plusSeconds(1), Duration.ofSeconds(1),
                ProcessHandle.current().pid(), stdout, stderr, false, false, "");
    }
}
