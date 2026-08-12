package io.github.uprxiao.audit.adapter.trivy;

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
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrivyArtifactAdapterTest {
    private static final String FIXTURE = "/fixtures/trivy-artifact/0.73.0";
    private static final String CYCLONEDX_FIXTURE = "/fixtures/cyclonedx/2.9.3";
    @TempDir Path temporaryDirectory;

    @Test
    void preparesOfflinePinnedDatabaseScanOfCycloneDxAssetWithoutShell() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("task/raw/trivy-artifact"));
        copyReport(getClass(), CYCLONEDX_FIXTURE, "findings.json",
                Files.createDirectories(output.getParent().resolve("cyclonedx/sbom")).resolve("bom.json"), root);
        Path cache = initializedDatabase(temporaryDirectory.resolve("cache"));
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");
        TrivyArtifactAdapter adapter = new TrivyArtifactAdapter(cache);
        var specification = adapter.prepare(scan(project(root, "supply-fixture"), output),
                tools(TrivyArtifactAdapter.ID, executable, TrivyArtifactAdapter.TOOL_VERSION));
        assertDescriptorContract(adapter);
        assertSafeExecutionSpec(specification, temporaryDirectory.resolve("task"));
        assertTrue(specification.command().containsAll(java.util.List.of("sbom", "vuln,license",
                "--skip-db-update", "--offline-scan")));
        assertEquals("cyclonedx", adapter.descriptor().dependsOn().iterator().next().value());
    }

    @Test
    void goldenFindingIncludesPurlAliasesCurrentFixedAndDependencyPath() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("output"));
        Path report = copyReport(getClass(), FIXTURE, "findings.json", output.resolve("report.json"), root);
        var result = new TrivyArtifactAdapter(initializedDatabase(temporaryDirectory.resolve("cache")))
                .normalize(scan(project(root, "supply-fixture"), output),
                        artifacts(TrivyArtifactAdapter.ID, report, output));
        assertEquals(1, result.findings().size());
        var finding = result.findings().get(0);
        assertEquals(IssueCategory.DEPENDENCY_VULNERABILITY, finding.category());
        assertEquals("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", finding.component().purl());
        assertEquals("2.14.1", finding.component().version());
        assertEquals(java.util.List.of("2.17.1", "2.12.4"), finding.component().fixedVersions());
        assertEquals(java.util.List.of("supply-fixture", "pom.xml > org.apache.logging.log4j:log4j-core"),
                finding.component().dependencyPath());
        assertTrue(finding.identifiers().cve().contains("CVE-2021-44228"));
        assertTrue(finding.identifiers().ghsa().contains("GHSA-JFH8-C2JP-5V3Q"));
    }

    @Test
    void cleanPartialMalformedDatabaseUnavailableAndProcessFailureAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        var contextProject = project(root, "supply-fixture");
        Path cache = initializedDatabase(temporaryDirectory.resolve("cache"));
        TrivyArtifactAdapter adapter = new TrivyArtifactAdapter(cache);
        Path cleanOutput = Files.createDirectory(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.json", cleanOutput.resolve("report.json"), root);
        assertTrue(adapter.normalize(scan(contextProject, cleanOutput),
                artifacts(TrivyArtifactAdapter.ID, clean, cleanOutput)).findings().isEmpty());

        Path partialOutput = Files.createDirectory(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.json", partialOutput.resolve("report.json"), root);
        var partialResult = adapter.normalize(scan(contextProject, partialOutput),
                artifacts(TrivyArtifactAdapter.ID, partial, partialOutput));
        assertEquals(EngineStatus.PARTIAL, partialResult.coverage().status());
        assertEquals(2, partialResult.coverage().rawHitCount());
        assertEquals(1, partialResult.findings().size());

        Path malformedOutput = Files.createDirectory(temporaryDirectory.resolve("malformed"));
        Path malformed = copyReport(getClass(), FIXTURE, "malformed.json", malformedOutput.resolve("report.json"), root);
        RawArtifactSet malformedArtifacts = artifacts(TrivyArtifactAdapter.ID, malformed, malformedOutput);
        assertFalse(adapter.validate(malformedArtifacts).valid());
        assertThrows(IOException.class, () -> adapter.normalize(scan(contextProject, malformedOutput), malformedArtifacts));

        Path invalidCache = temporaryDirectory.resolve("invalid-db");
        copyReport(getClass(), FIXTURE, "database-unavailable.json",
                Files.createDirectories(invalidCache.resolve("db")).resolve("metadata.json"), root);
        TrivyArtifactAdapter missingDb = new TrivyArtifactAdapter(invalidCache);
        assertEquals("VULNERABILITY_DATABASE_UNAVAILABLE",
                missingDb.checkApplicability(contextProject,
                        tools(TrivyArtifactAdapter.ID, Path.of(System.getProperty("java.home"), "bin", "java"),
                                TrivyArtifactAdapter.TOOL_VERSION)).reasonCode());
        assertThrows(IOException.class, () -> missingDb.normalize(scan(contextProject, cleanOutput),
                artifacts(TrivyArtifactAdapter.ID, clean, cleanOutput)));

        Path incompleteCache = initializedDatabase(temporaryDirectory.resolve("incomplete-java-db"));
        Files.delete(incompleteCache.resolve("java-db/trivy-java.db"));
        TrivyArtifactAdapter missingJavaDb = new TrivyArtifactAdapter(incompleteCache);
        assertEquals("VULNERABILITY_DATABASE_UNAVAILABLE",
                missingJavaDb.checkApplicability(contextProject,
                        tools(TrivyArtifactAdapter.ID, Path.of(System.getProperty("java.home"), "bin", "java"),
                                TrivyArtifactAdapter.TOOL_VERSION)).reasonCode());

        RawArtifactSet failed = new RawArtifactSet(TrivyArtifactAdapter.ID, Map.of("report", clean),
                execution(cleanOutput, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void realMacSmokeWhenExecutableAndDatabaseAreProvided() throws Exception {
        String executable = System.getProperty("audit.trivy.executable", "");
        String cacheValue = System.getProperty("audit.trivy.cache", "");
        Assumptions.assumeTrue(!executable.isBlank() && !cacheValue.isBlank());
        Path cache = Path.of(cacheValue).toAbsolutePath().normalize();
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("task/raw/trivy-artifact"));
        copyReport(getClass(), CYCLONEDX_FIXTURE, "findings.json",
                Files.createDirectories(output.getParent().resolve("cyclonedx/sbom")).resolve("bom.json"), root);
        TrivyArtifactAdapter adapter = new TrivyArtifactAdapter(cache);
        var context = scan(project(root, "supply-fixture"), output);
        ExecutionResult process = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(TrivyArtifactAdapter.ID, Path.of(executable), TrivyArtifactAdapter.TOOL_VERSION)),
                CancellationToken.NONE);
        var result = adapter.normalize(context, new RawArtifactSet(TrivyArtifactAdapter.ID,
                Map.of("report", output.resolve("report.json")), process));
        assertEquals(ExecutionResult.Status.SUCCEEDED, process.status());
        assertFalse(result.findings().isEmpty());
    }

    private Path initializedDatabase(Path cache) throws IOException {
        Path metadata = Files.createDirectories(cache.resolve("db")).resolve("metadata.json");
        Files.writeString(metadata, "{\"Version\":2,\"UpdatedAt\":\"" + Instant.now() + "\"}");
        Files.writeString(metadata.getParent().resolve("trivy.db"), "fixture-database-sentinel");
        Path javaMetadata = Files.createDirectories(cache.resolve("java-db")).resolve("metadata.json");
        Files.writeString(javaMetadata, "{\"Version\":2,\"UpdatedAt\":\"" + Instant.now() + "\"}");
        Files.writeString(javaMetadata.getParent().resolve("trivy-java.db"), "fixture-java-database-sentinel");
        return cache;
    }
}
