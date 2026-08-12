package io.github.uprxiao.audit.adapter.cyclonedx;

import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.*;
import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertDescriptorContract;
import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertSafeExecutionSpec;
import static org.junit.jupiter.api.Assertions.*;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CycloneDxAdapterTest {
    private static final String FIXTURE = "/fixtures/cyclonedx/2.9.3";
    @TempDir Path temporaryDirectory;

    @Test
    void preparesPinnedMavenPluginAndSbomAssetWithoutShell() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = temporaryDirectory.resolve("task/raw/cyclonedx");
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");
        CycloneDxAdapter adapter = new CycloneDxAdapter();
        var specification = adapter.prepare(scan(project(root, "supply-fixture"), output),
                tools(CycloneDxAdapter.ID, executable, CycloneDxAdapter.TOOL_VERSION));
        assertDescriptorContract(adapter);
        assertSafeExecutionSpec(specification, temporaryDirectory.resolve("task"));
        assertTrue(specification.command().contains(CycloneDxAdapter.MAVEN_COORDINATE));
        assertTrue(specification.expectedArtifacts().stream()
                .anyMatch(artifact -> artifact.relativePath().equals("sbom/bom.json")));
    }

    @Test
    void inventoryNeverInflatesFindingCountAndAssetPathIsStable() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("output"));
        Path sbom = copyReport(getClass(), FIXTURE, "findings.json", output.resolve("bom.json"), root);
        var result = new CycloneDxAdapter().normalize(scan(project(root, "supply-fixture"), output),
                new RawArtifactSet(CycloneDxAdapter.ID, Map.of("sbom", sbom),
                        execution(output, ExecutionResult.Status.SUCCEEDED, 0)));
        assertTrue(result.findings().isEmpty());
        assertEquals(0, result.coverage().rawHitCount());
        assertEquals("sbom/bom.json", result.coverage().artifact());
    }

    @Test
    void cleanPartialMalformedAndProcessFailureAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        var contextProject = project(root, "supply-fixture");
        CycloneDxAdapter adapter = new CycloneDxAdapter();
        assertEquals(io.github.uprxiao.audit.scanner.Applicability.Status.APPLICABLE,
                adapter.checkApplicability(contextProject,
                        tools(CycloneDxAdapter.ID, Path.of(System.getProperty("java.home"), "bin", "java"),
                                CycloneDxAdapter.TOOL_VERSION)).status(),
                "SBOM generation has no vulnerability-database precondition");
        Path cleanOutput = Files.createDirectory(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.json", cleanOutput.resolve("bom.json"), root);
        assertTrue(adapter.normalize(scan(contextProject, cleanOutput),
                new RawArtifactSet(CycloneDxAdapter.ID, Map.of("sbom", clean),
                        execution(cleanOutput, ExecutionResult.Status.SUCCEEDED, 0))).warnings().isEmpty());

        Path partialOutput = Files.createDirectory(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.json", partialOutput.resolve("bom.json"), root);
        var partialResult = adapter.normalize(scan(contextProject, partialOutput),
                new RawArtifactSet(CycloneDxAdapter.ID, Map.of("sbom", partial),
                        execution(partialOutput, ExecutionResult.Status.SUCCEEDED, 0)));
        assertEquals(EngineStatus.PARTIAL, partialResult.coverage().status());

        Path malformedOutput = Files.createDirectory(temporaryDirectory.resolve("malformed"));
        Path malformed = copyReport(getClass(), FIXTURE, "malformed.json", malformedOutput.resolve("bom.json"), root);
        RawArtifactSet malformedArtifacts = new RawArtifactSet(CycloneDxAdapter.ID, Map.of("sbom", malformed),
                execution(malformedOutput, ExecutionResult.Status.SUCCEEDED, 0));
        assertFalse(adapter.validate(malformedArtifacts).valid());
        assertThrows(IOException.class, () -> adapter.normalize(scan(contextProject, malformedOutput), malformedArtifacts));

        RawArtifactSet failed = new RawArtifactSet(CycloneDxAdapter.ID, Map.of("sbom", clean),
                execution(cleanOutput, ExecutionResult.Status.FAILED, 1));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void realMacJdk17MavenSmokeWhenExecutableIsProvided() throws Exception {
        String configured = System.getProperty("audit.maven.executable", "");
        Assumptions.assumeTrue(!configured.isBlank());
        assertEquals("17", System.getProperty("java.specification.version"));
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("task/raw/cyclonedx"));
        CycloneDxAdapter adapter = new CycloneDxAdapter();
        var context = scan(project(root, "supply-fixture"), output);
        ExecutionResult process = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(CycloneDxAdapter.ID, Path.of(configured), CycloneDxAdapter.TOOL_VERSION)),
                CancellationToken.NONE);
        Path sbom = output.resolve("sbom/bom.json");
        var result = adapter.normalize(context,
                new RawArtifactSet(CycloneDxAdapter.ID, Map.of("sbom", sbom), process));
        assertTrue(result.findings().isEmpty());
        assertTrue(Files.size(sbom) > 0);
    }
}
