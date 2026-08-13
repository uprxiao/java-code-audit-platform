package io.github.uprxiao.audit.adapter.semgrep;

import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertDescriptorContract;
import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertSafeExecutionSpec;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.uprxiao.audit.finding.Confidence;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.Severity;
import io.github.uprxiao.audit.finding.SourceType;
import io.github.uprxiao.audit.intake.MavenModule;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.intake.ProjectManifest;
import io.github.uprxiao.audit.intake.SourceDescriptor;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SemgrepAdapterTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void adapterContractAndPreparedCommandAreSafe() throws Exception {
        Path rules = Files.writeString(temporaryDirectory.resolve("rules.yaml"), "rules: []\n");
        Path projectRoot = copyProject(temporaryDirectory.resolve("contract-project"));
        ProjectContext project = project(projectRoot);
        Path output = temporaryDirectory.resolve("task/raw/semgrep");
        ScanContext scan = new ScanContext(UUID.randomUUID(), ScanProfile.QUICK, project, output, null, null);
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");
        ToolContext tools = tools(executable, "1.170.0");
        SemgrepAdapter adapter = new SemgrepAdapter(rules);

        assertDescriptorContract(adapter);
        assertEquals(io.github.uprxiao.audit.scanner.Applicability.Status.APPLICABLE,
                adapter.checkApplicability(project, tools).status());
        ExecutionSpec specification = adapter.prepare(scan, tools);
        assertSafeExecutionSpec(specification, temporaryDirectory.resolve("task"));
        assertFalse(specification.command().contains("sh"));
        assertTrue(specification.command().contains("--metrics=off"));
        assertEquals("1", specification.environment().get("PYTHONDONTWRITEBYTECODE"));
    }

    @Test
    void goldenFindingNormalizesWithoutLosingEvidence() throws Exception {
        Path projectRoot = copyProject(temporaryDirectory.resolve("finding-project"));
        ProjectContext project = project(projectRoot);
        Path output = Files.createDirectories(temporaryDirectory.resolve("finding-output"));
        Path report = copyReport("findings.json", output.resolve("report.json"), projectRoot);
        SemgrepAdapter adapter = new SemgrepAdapter(temporaryDirectory.resolve("rules.yaml"));

        NormalizationResult normalized = adapter.normalize(scan(project, output), artifacts(report, output));

        assertEquals(1, normalized.findings().size());
        var finding = normalized.findings().get(0);
        assertEquals(IssueCategory.WEB_SECURITY, finding.category());
        assertEquals(Severity.P1, finding.severity());
        assertEquals(Confidence.HIGH, finding.confidence());
        assertEquals("SQL_INJECTION", finding.ruleFamily());
        assertEquals("src/main/java/example/UnsafeController.java", finding.location().path());
        assertEquals(7, finding.location().startLine());
        assertTrue(finding.snippet().text().contains("executeQuery"));
        assertEquals(Set.of("CWE-89"), Set.copyOf(finding.identifiers().cwe()));
        assertEquals("semgrep", finding.evidence().get(0).engine());
        assertEquals(EngineStatus.SUCCEEDED, normalized.coverage().status());
    }

    @Test
    void cleanPartialMalformedAndFailedExecutionHaveDistinctOutcomes() throws Exception {
        Path projectRoot = copyProject(temporaryDirectory.resolve("outcome-project"));
        ProjectContext project = project(projectRoot);
        SemgrepAdapter adapter = new SemgrepAdapter(temporaryDirectory.resolve("rules.yaml"));

        Path cleanOutput = Files.createDirectory(temporaryDirectory.resolve("clean-output"));
        Path clean = copyReport("clean.json", cleanOutput.resolve("report.json"), projectRoot);
        NormalizationResult cleanResult = adapter.normalize(scan(project, cleanOutput), artifacts(clean, cleanOutput));
        assertTrue(cleanResult.findings().isEmpty());
        assertEquals(EngineStatus.SUCCEEDED, cleanResult.coverage().status());

        Path partialOutput = Files.createDirectory(temporaryDirectory.resolve("partial-output"));
        Path partial = copyReport("partial.json", partialOutput.resolve("report.json"), projectRoot);
        NormalizationResult partialResult = adapter.normalize(scan(project, partialOutput), artifacts(partial, partialOutput));
        assertEquals(EngineStatus.PARTIAL, partialResult.coverage().status());
        assertEquals(1, partialResult.warnings().size());

        Path malformedOutput = Files.createDirectory(temporaryDirectory.resolve("malformed-output"));
        Path malformed = copyReport("malformed.json", malformedOutput.resolve("report.json"), projectRoot);
        ArtifactValidation malformedValidation = adapter.validate(artifacts(malformed, malformedOutput));
        assertFalse(malformedValidation.valid());
        assertTrue(malformedValidation.errors().contains("REPORT_JSON_INVALID"));
        assertThrows(IOException.class,
                () -> adapter.normalize(scan(project, malformedOutput), artifacts(malformed, malformedOutput)));

        RawArtifactSet failed = new RawArtifactSet(SemgrepAdapter.ID, Map.of("report", clean),
                execution(cleanOutput, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void realSemgrep170SmokeWhenExecutableIsProvided() throws Exception {
        String configured = System.getProperty("audit.semgrep.executable", "");
        Assumptions.assumeTrue(!configured.isBlank(), "real Semgrep path is only required in the smoke profile");
        Path executable = Path.of(configured).toAbsolutePath().normalize();
        Assumptions.assumeTrue(Files.isExecutable(executable));
        Path rules = Path.of(System.getProperty("audit.semgrep.rules",
                "../../config/rules/semgrep/java-audit.yaml")).toAbsolutePath().normalize();
        Path projectRoot = copyProject(temporaryDirectory.resolve("real-project"));
        ProjectContext project = project(projectRoot);
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        SemgrepAdapter adapter = new SemgrepAdapter(rules);
        ScanContext scan = scan(project, output);
        ExecutionSpec specification = adapter.prepare(scan, tools(executable, "1.170.0"));

        ExecutionResult execution = new LocalProcessExecutionBackend().execute(specification, CancellationToken.NONE);
        RawArtifactSet artifacts = new RawArtifactSet(SemgrepAdapter.ID,
                Map.of("report", output.resolve("report.json")), execution);
        NormalizationResult result = adapter.normalize(scan, artifacts);

        assertEquals(ExecutionResult.Status.SUCCEEDED, execution.status());
        assertEquals(2, result.findings().size());
        assertTrue(result.findings().stream().anyMatch(finding -> finding.ruleFamily().equals("SQL_INJECTION")));
        assertTrue(result.findings().stream().anyMatch(finding -> finding.ruleFamily().equals("COMMAND_INJECTION")));
    }

    private ProjectContext project(Path root) {
        SourceDescriptor source = new SourceDescriptor(SourceType.ZIP, "fixture", "fixture.zip", "", "sha256");
        ProjectManifest manifest = new ProjectManifest(1, ".", "pom.xml", 17, "jar",
                java.util.List.of(new MavenModule(".", "semgrep-fixture", "jar")), source,
                Set.of(ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP), java.util.List.of());
        return new ProjectContext(root, manifest);
    }

    private ScanContext scan(ProjectContext project, Path output) {
        return new ScanContext(UUID.randomUUID(), ScanProfile.QUICK, project, output, null, null);
    }

    private ToolContext tools(Path executable, String version) {
        return new ToolContext(executable.getParent(), Map.of(SemgrepAdapter.ID,
                new ToolContext.ToolInstallation(executable, version, true)));
    }

    private RawArtifactSet artifacts(Path report, Path output) throws Exception {
        return new RawArtifactSet(SemgrepAdapter.ID, Map.of("report", report),
                execution(output, ExecutionResult.Status.SUCCEEDED, 0));
    }

    private ExecutionResult execution(Path output, ExecutionResult.Status status, Integer exitCode) throws Exception {
        Path stdout = output.resolve("stdout.log");
        Path stderr = output.resolve("stderr.log");
        Files.writeString(stdout, "");
        Files.writeString(stderr, "");
        Instant started = Instant.parse("2026-08-12T00:00:00Z");
        return new ExecutionResult(status, exitCode, started, started.plusSeconds(1), Duration.ofSeconds(1),
                ProcessHandle.current().pid(), stdout, stderr, false, false, "");
    }

    private Path copyProject(Path destination) throws Exception {
        Path resource = Path.of(getClass().getResource("/fixtures/semgrep/1.170.0/project").toURI());
        try (var paths = Files.walk(resource)) {
            for (Path source : paths.toList()) {
                Path target = destination.resolve(resource.relativize(source).toString());
                if (Files.isDirectory(source)) {
                    Files.createDirectories(target);
                } else {
                    Files.copy(source, target);
                }
            }
        }
        return destination.toAbsolutePath().normalize();
    }

    private Path copyReport(String name, Path destination, Path projectRoot) throws Exception {
        try (InputStream input = getClass().getResourceAsStream("/fixtures/semgrep/1.170.0/" + name)) {
            String content = new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8)
                    .replace("@PROJECT_ROOT@", projectRoot.toString().replace("\\", "\\\\"));
            Files.writeString(destination, content);
        }
        return destination;
    }
}
