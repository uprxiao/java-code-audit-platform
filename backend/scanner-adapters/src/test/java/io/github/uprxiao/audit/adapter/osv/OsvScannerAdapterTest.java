package io.github.uprxiao.audit.adapter.osv;

import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.*;
import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertDescriptorContract;
import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertSafeExecutionSpec;
import static org.junit.jupiter.api.Assertions.*;

import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.IssueCategory;
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

class OsvScannerAdapterTest {
    private static final String FIXTURE = "/fixtures/osv-scanner/2.3.8";
    @TempDir Path temporaryDirectory;

    @Test
    void preparesFixedSourceScanWithoutShell() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        OsvScannerAdapter adapter = new OsvScannerAdapter();
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");
        var specification = adapter.prepare(scan(project(root, "supply-fixture"),
                        temporaryDirectory.resolve("task/raw/osv-scanner")),
                tools(OsvScannerAdapter.ID, executable, OsvScannerAdapter.TOOL_VERSION));
        assertDescriptorContract(adapter);
        assertSafeExecutionSpec(specification, temporaryDirectory.resolve("task"));
        assertTrue(specification.command().containsAll(java.util.List.of("scan", "source", "--recursive", "json")));
        assertTrue(specification.command().contains("--no-resolve"),
                "untrusted POMs must not trigger OSV's risky transitive enricher");
    }

    @Test
    void goldenFindingIncludesPurlAliasesCurrentFixedAndManifestPath() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("output"));
        Path report = copyReport(getClass(), FIXTURE, "findings.json", output.resolve("report.json"), root);
        var result = new OsvScannerAdapter().normalize(scan(project(root, "supply-fixture"), output),
                artifacts(OsvScannerAdapter.ID, report, output));
        assertEquals(1, result.findings().size());
        var finding = result.findings().get(0);
        assertEquals(IssueCategory.DEPENDENCY_VULNERABILITY, finding.category());
        assertEquals("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", finding.component().purl());
        assertEquals(java.util.List.of("2.17.1"), finding.component().fixedVersions());
        assertEquals(java.util.List.of("pom.xml"), finding.component().dependencyPath());
        assertTrue(finding.identifiers().cve().contains("CVE-2021-44228"));
        assertTrue(finding.identifiers().ghsa().contains("GHSA-JFH8-C2JP-5V3Q"));
    }

    @Test
    void cleanPartialMalformedDatabaseFailureAndProcessFailureAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        var contextProject = project(root, "supply-fixture");
        OsvScannerAdapter adapter = new OsvScannerAdapter();
        Path cleanOutput = Files.createDirectory(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.json", cleanOutput.resolve("report.json"), root);
        assertTrue(adapter.normalize(scan(contextProject, cleanOutput),
                artifacts(OsvScannerAdapter.ID, clean, cleanOutput)).findings().isEmpty());

        Path partialOutput = Files.createDirectory(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.json", partialOutput.resolve("report.json"), root);
        var partialResult = adapter.normalize(scan(contextProject, partialOutput),
                artifacts(OsvScannerAdapter.ID, partial, partialOutput));
        assertEquals(EngineStatus.PARTIAL, partialResult.coverage().status());
        assertEquals(2, partialResult.coverage().rawHitCount());
        assertEquals(1, partialResult.findings().size());

        Path malformedOutput = Files.createDirectory(temporaryDirectory.resolve("malformed"));
        Path malformed = copyReport(getClass(), FIXTURE, "malformed.json", malformedOutput.resolve("report.json"), root);
        assertFalse(adapter.validate(artifacts(OsvScannerAdapter.ID, malformed, malformedOutput)).valid());
        Path unavailable = copyReport(getClass(), FIXTURE, "database-unavailable.json",
                malformedOutput.resolve("unavailable.json"), root);
        RawArtifactSet networkFailure = new RawArtifactSet(OsvScannerAdapter.ID, Map.of("report", unavailable),
                execution(malformedOutput, ExecutionResult.Status.FAILED, 129));
        assertTrue(adapter.validate(networkFailure).errors().contains("EXECUTION_FAILED"));
        RawArtifactSet findingsExit = new RawArtifactSet(OsvScannerAdapter.ID, Map.of("report", clean),
                execution(cleanOutput, ExecutionResult.Status.FAILED, 1));
        assertTrue(adapter.validate(findingsExit).valid(), "OSV exit 1 is the documented findings status");
    }

    @Test
    void realMacSmokeWhenExecutableIsProvided() throws Exception {
        String configured = System.getProperty("audit.osv.executable", "");
        Assumptions.assumeTrue(!configured.isBlank());
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        OsvScannerAdapter adapter = new OsvScannerAdapter();
        var context = scan(project(root, "supply-fixture"), output);
        ExecutionResult process = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(OsvScannerAdapter.ID, Path.of(configured), OsvScannerAdapter.TOOL_VERSION)),
                CancellationToken.NONE);
        var normalized = adapter.normalize(context,
                new RawArtifactSet(OsvScannerAdapter.ID, Map.of("report", output.resolve("report.json")), process));
        assertFalse(normalized.findings().isEmpty());
        assertTrue(normalized.findings().stream().allMatch(finding -> finding.component().purl().contains("@")));
    }
}
