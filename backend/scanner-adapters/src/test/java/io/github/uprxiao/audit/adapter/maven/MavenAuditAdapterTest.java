package io.github.uprxiao.audit.adapter.maven;

import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.*;
import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertDescriptorContract;
import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertSafeExecutionSpec;
import static org.junit.jupiter.api.Assertions.*;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MavenAuditAdapterTest {
    private static final String DEPENDENCY_FIXTURE = "/fixtures/maven-dependency-analysis/3.9.0";
    private static final String ENFORCER_FIXTURE = "/fixtures/maven-enforcer/3.6.2";
    @TempDir Path temporaryDirectory;

    @Test
    void commandsAreFixedAndDoNotAcceptRequestProfilesPropertiesSettingsOrGoals() throws Exception {
        Path root = copyProject(getClass(), DEPENDENCY_FIXTURE, temporaryDirectory.resolve("project"));
        Path maven = Files.writeString(temporaryDirectory.resolve("mvn"), "fixture");
        maven.toFile().setExecutable(true);
        MavenDependencyAnalysisAdapter dependency = new MavenDependencyAnalysisAdapter(temporaryDirectory.resolve("m2"));
        var dependencySpec = dependency.prepare(scan(project(root, "dependency-fixture"),
                        temporaryDirectory.resolve("task/raw/maven-dependency-analysis")),
                tools(dependency.descriptor().id(), maven, MavenDependencyAnalysisAdapter.TOOL_VERSION));
        assertDescriptorContract(dependency);
        assertSafeExecutionSpec(dependencySpec, temporaryDirectory.resolve("task"));
        assertTrue(dependencySpec.command().contains("org.apache.maven.plugins:maven-dependency-plugin:3.9.0:analyze"));
        assertFalse(dependencySpec.command().contains("--settings"));
        assertFalse(dependencySpec.command().stream().anyMatch(value -> value.startsWith("-P")));

        MavenEnforcerAdapter enforcer = new MavenEnforcerAdapter(temporaryDirectory.resolve("m2"));
        var enforcerSpec = enforcer.prepare(scan(project(root, "dependency-fixture"),
                        temporaryDirectory.resolve("task/raw/maven-enforcer")),
                tools(enforcer.descriptor().id(), maven, MavenEnforcerAdapter.TOOL_VERSION));
        assertTrue(enforcerSpec.command().contains("org.apache.maven.plugins:maven-enforcer-plugin:3.6.2:enforce"));
        assertTrue(enforcerSpec.command().contains("-Drules=dependencyConvergence"));
        assertFalse(enforcerSpec.command().contains("--settings"));
    }

    @Test
    void dependencyGoldenContractsCoverCleanFindingsPartialMalformedAndProcessFailure() throws Exception {
        Path root = copyProject(getClass(), DEPENDENCY_FIXTURE, temporaryDirectory.resolve("dependency-project"));
        MavenDependencyAnalysisAdapter adapter = new MavenDependencyAnalysisAdapter(temporaryDirectory.resolve("m2"));
        Path findingsOut = Files.createDirectories(temporaryDirectory.resolve("dependency-findings"));
        Path findingsLog = copyReport(getClass(), DEPENDENCY_FIXTURE, "findings.log",
                findingsOut.resolve("stdout.log"), root);
        var normalized = adapter.normalize(scan(project(root, "dependency-fixture"), findingsOut),
                artifacts(MavenDependencyAnalysisAdapter.ID, findingsLog, findingsOut));
        assertEquals(2, normalized.findings().size());
        assertEquals(IssueCategory.BUILD_GOVERNANCE, normalized.findings().get(0).category());
        assertTrue(normalized.findings().stream().allMatch(value -> value.fingerprint().matches("sha256:[0-9a-f]{64}")));
        assertTrue(normalized.findings().stream().map(value -> value.ruleFamily()).toList()
                .containsAll(java.util.List.of("USED_UNDECLARED_DEPENDENCY", "UNUSED_DECLARED_DEPENDENCY")));

        Path cleanOut = Files.createDirectories(temporaryDirectory.resolve("dependency-clean"));
        Path clean = copyReport(getClass(), DEPENDENCY_FIXTURE, "clean.log", cleanOut.resolve("stdout.log"), root);
        assertTrue(adapter.normalize(scan(project(root, "dependency-fixture"), cleanOut),
                artifacts(MavenDependencyAnalysisAdapter.ID, clean, cleanOut)).findings().isEmpty());
        Path partialOut = Files.createDirectories(temporaryDirectory.resolve("dependency-partial"));
        Path partial = copyReport(getClass(), DEPENDENCY_FIXTURE, "partial.log", partialOut.resolve("stdout.log"), root);
        assertEquals(EngineStatus.PARTIAL, adapter.normalize(scan(project(root, "dependency-fixture"), partialOut),
                artifacts(MavenDependencyAnalysisAdapter.ID, partial, partialOut)).coverage().status());
        Path badOut = Files.createDirectories(temporaryDirectory.resolve("dependency-bad"));
        Path bad = copyReport(getClass(), DEPENDENCY_FIXTURE, "malformed.log", badOut.resolve("stdout.log"), root);
        assertFalse(adapter.validate(artifacts(MavenDependencyAnalysisAdapter.ID, bad, badOut)).valid());
        assertThrows(IOException.class, () -> adapter.normalize(scan(project(root, "dependency-fixture"), badOut),
                artifacts(MavenDependencyAnalysisAdapter.ID, bad, badOut)));
        RawArtifactSet failed = new RawArtifactSet(MavenDependencyAnalysisAdapter.ID, Map.of("report", clean),
                execution(cleanOut, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void enforcerGoldenContractsTreatRecognizedPolicyExitOneAsFindings() throws Exception {
        Path root = copyProject(getClass(), ENFORCER_FIXTURE, temporaryDirectory.resolve("enforcer-project"));
        MavenEnforcerAdapter adapter = new MavenEnforcerAdapter(temporaryDirectory.resolve("m2"));
        Path findingsOut = Files.createDirectories(temporaryDirectory.resolve("enforcer-findings"));
        Path findingsLog = copyReport(getClass(), ENFORCER_FIXTURE, "findings.log", findingsOut.resolve("stdout.log"), root);
        RawArtifactSet findings = new RawArtifactSet(MavenEnforcerAdapter.ID, Map.of("report", findingsLog),
                execution(findingsOut, ExecutionResult.Status.FAILED, 1));
        assertTrue(adapter.validate(findings).valid());
        var normalized = adapter.normalize(scan(project(root, "enforcer-fixture"), findingsOut), findings);
        assertEquals(1, normalized.findings().size());
        assertEquals("DEPENDENCY_CONVERGENCE", normalized.findings().get(0).ruleFamily());

        Path cleanOut = Files.createDirectories(temporaryDirectory.resolve("enforcer-clean"));
        Path clean = copyReport(getClass(), ENFORCER_FIXTURE, "clean.log", cleanOut.resolve("stdout.log"), root);
        assertTrue(adapter.normalize(scan(project(root, "enforcer-fixture"), cleanOut),
                artifacts(MavenEnforcerAdapter.ID, clean, cleanOut)).findings().isEmpty());
        Path partialOut = Files.createDirectories(temporaryDirectory.resolve("enforcer-partial"));
        Path partial = copyReport(getClass(), ENFORCER_FIXTURE, "partial.log", partialOut.resolve("stdout.log"), root);
        assertEquals(EngineStatus.PARTIAL, adapter.normalize(scan(project(root, "enforcer-fixture"), partialOut),
                artifacts(MavenEnforcerAdapter.ID, partial, partialOut)).coverage().status());
        Path badOut = Files.createDirectories(temporaryDirectory.resolve("enforcer-bad"));
        Path bad = copyReport(getClass(), ENFORCER_FIXTURE, "malformed.log", badOut.resolve("stdout.log"), root);
        assertFalse(adapter.validate(artifacts(MavenEnforcerAdapter.ID, bad, badOut)).valid());
        RawArtifactSet failed = new RawArtifactSet(MavenEnforcerAdapter.ID, Map.of("report", clean),
                execution(cleanOut, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void realSystemMavenDependencyAndEnforcerSmoke() throws Exception {
        String mavenProperty = System.getProperty("audit.standard.maven", "");
        Assumptions.assumeTrue(!mavenProperty.isBlank());
        Path maven = Path.of(mavenProperty).toAbsolutePath().normalize();
        var backend = new LocalProcessExecutionBackend();

        Path dependencyRoot = copyProject(getClass(), DEPENDENCY_FIXTURE, temporaryDirectory.resolve("real-dependency-project"));
        Path dependencyOut = Files.createDirectories(temporaryDirectory.resolve("real-dependency-output"));
        MavenDependencyAnalysisAdapter dependency = new MavenDependencyAnalysisAdapter(temporaryDirectory.resolve("real-m2"));
        var dependencyContext = scan(project(dependencyRoot, "dependency-fixture"), dependencyOut);
        ExecutionResult dependencyExecution = backend.execute(dependency.prepare(dependencyContext,
                tools(MavenDependencyAnalysisAdapter.ID, maven, MavenDependencyAnalysisAdapter.TOOL_VERSION)), CancellationToken.NONE);
        assertEquals(ExecutionResult.Status.SUCCEEDED, dependencyExecution.status());
        Path dependencyReport = copyStdout(dependencyExecution, dependencyOut);
        RawArtifactSet dependencyArtifacts = new RawArtifactSet(MavenDependencyAnalysisAdapter.ID,
                Map.of("report", dependencyReport), dependencyExecution);
        assertTrue(dependency.validate(dependencyArtifacts).valid());
        assertTrue(dependency.normalize(dependencyContext, dependencyArtifacts).findings().stream()
                .anyMatch(value -> value.ruleFamily().equals("UNUSED_DECLARED_DEPENDENCY")));

        Path enforcerRoot = copyProject(getClass(), ENFORCER_FIXTURE, temporaryDirectory.resolve("real-enforcer-project"));
        Path enforcerOut = Files.createDirectories(temporaryDirectory.resolve("real-enforcer-output"));
        MavenEnforcerAdapter enforcer = new MavenEnforcerAdapter(temporaryDirectory.resolve("real-m2"));
        var enforcerContext = scan(project(enforcerRoot, "enforcer-fixture"), enforcerOut);
        ExecutionResult enforcerExecution = backend.execute(enforcer.prepare(enforcerContext,
                tools(MavenEnforcerAdapter.ID, maven, MavenEnforcerAdapter.TOOL_VERSION)), CancellationToken.NONE);
        assertEquals(ExecutionResult.Status.SUCCEEDED, enforcerExecution.status());
        Path enforcerReport = copyStdout(enforcerExecution, enforcerOut);
        assertTrue(enforcer.validate(new RawArtifactSet(MavenEnforcerAdapter.ID,
                Map.of("report", enforcerReport), enforcerExecution)).valid());
    }

    private Path copyStdout(ExecutionResult result, Path output) throws IOException {
        Path report = output.resolve("process-output.log");
        Files.copy(result.stdout(), report);
        return report;
    }
}
