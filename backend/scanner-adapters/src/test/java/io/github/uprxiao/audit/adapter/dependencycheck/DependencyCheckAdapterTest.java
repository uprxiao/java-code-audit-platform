package io.github.uprxiao.audit.adapter.dependencycheck;

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
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DependencyCheckAdapterTest {
    private static final String FIXTURE = "/fixtures/dependency-check/12.2.2";
    @TempDir Path temporaryDirectory;

    @Test
    void preparesFixedOfflineDatabaseCommandWithoutShell() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path data = initializedDatabase(temporaryDirectory.resolve("database"));
        DependencyCheckAdapter adapter = new DependencyCheckAdapter(data);
        Path output = temporaryDirectory.resolve("task/raw/dependency-check");
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");
        var specification = adapter.prepare(scan(project(root, "supply-fixture"), output),
                tools(DependencyCheckAdapter.ID, executable, DependencyCheckAdapter.TOOL_VERSION));
        assertDescriptorContract(adapter);
        assertSafeExecutionSpec(specification, temporaryDirectory.resolve("task"));
        assertTrue(specification.command().contains("--noupdate"));
        assertTrue(specification.command().contains("--data"));
        assertTrue(specification.command().contains("--disableOssIndex"));
        assertTrue(specification.command().contains("--disableCentral"));
        assertEquals("17", System.getProperty("java.specification.version"));
    }

    @Test
    void scansOnlyExternalMavenRuntimeArtifactsAfterTheControlledBuild() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project-with-classpath"));
        Path external = temporaryDirectory.resolve(
                "service-cache/maven/repository/org/example/demo/1.0/demo-1.0.jar").toAbsolutePath();
        Files.createDirectories(external.getParent());
        Files.writeString(external, "fixture");
        Path reactorArtifact = root.resolve("target/supply-fixture-1.0.jar").toAbsolutePath();
        Files.createDirectories(reactorArtifact.getParent());
        Files.writeString(reactorArtifact, "fixture");
        Files.writeString(root.resolve("target/audit-runtime-classpath.txt"),
                reactorArtifact + java.io.File.pathSeparator + external);

        Path output = temporaryDirectory.resolve("task-with-classpath/raw/dependency-check");
        var specification = new DependencyCheckAdapter(initializedDatabase(temporaryDirectory.resolve("database-2")))
                .prepare(scan(project(root, "supply-fixture"), output),
                        tools(DependencyCheckAdapter.ID, Path.of(System.getProperty("java.home"), "bin", "java"),
                                DependencyCheckAdapter.TOOL_VERSION));

        int scan = specification.command().indexOf("--scan");
        assertTrue(scan > 0);
        assertEquals(external.toString(), specification.command().get(scan + 1));
        assertFalse(specification.command().contains(root.toString()));
        assertFalse(specification.command().contains(reactorArtifact.toString()));
        assertEquals(1, specification.command().stream().filter("--scan"::equals).count());
    }

    @Test
    void normalizesStrictPurlIdentifiersVersionsAndPath() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("output"));
        Path report = copyReport(getClass(), FIXTURE, "findings.json", output.resolve("report.json"), root);
        var result = new DependencyCheckAdapter(initializedDatabase(temporaryDirectory.resolve("database")))
                .normalize(scan(project(root, "supply-fixture"), output),
                        artifacts(DependencyCheckAdapter.ID, report, output));
        assertEquals(1, result.findings().size());
        var finding = result.findings().get(0);
        assertEquals(IssueCategory.DEPENDENCY_VULNERABILITY, finding.category());
        assertEquals("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", finding.component().purl());
        assertEquals("2.14.1", finding.component().version());
        assertEquals(java.util.List.of("2.17.1"), finding.component().fixedVersions());
        assertTrue(finding.identifiers().cve().contains("CVE-2021-44228"));
        assertTrue(finding.identifiers().ghsa().contains("GHSA-JFH8-C2JP-5V3Q"));
        assertEquals(java.util.List.of("supply-fixture", "org.apache.logging.log4j:log4j-core:2.14.1"),
                finding.component().dependencyPath());
        assertTrue(finding.fingerprint().matches("sha256:[0-9a-f]{64}"));
    }

    @Test
    void cleanPartialMalformedDatabaseUnavailableAndProcessFailureAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        var contextProject = project(root, "supply-fixture");
        Path data = initializedDatabase(temporaryDirectory.resolve("database"));
        DependencyCheckAdapter adapter = new DependencyCheckAdapter(data);
        Path cleanOutput = Files.createDirectory(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.json", cleanOutput.resolve("report.json"), root);
        assertTrue(adapter.normalize(scan(contextProject, cleanOutput),
                artifacts(DependencyCheckAdapter.ID, clean, cleanOutput)).findings().isEmpty());

        Path partialOutput = Files.createDirectory(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.json", partialOutput.resolve("report.json"), root);
        var partialResult = adapter.normalize(scan(contextProject, partialOutput),
                artifacts(DependencyCheckAdapter.ID, partial, partialOutput));
        assertEquals(EngineStatus.PARTIAL, partialResult.coverage().status());
        assertEquals(2, partialResult.coverage().rawHitCount());
        assertEquals(1, partialResult.findings().size());

        Path malformedOutput = Files.createDirectory(temporaryDirectory.resolve("malformed"));
        Path malformed = copyReport(getClass(), FIXTURE, "malformed.json", malformedOutput.resolve("report.json"), root);
        assertFalse(adapter.validate(artifacts(DependencyCheckAdapter.ID, malformed, malformedOutput)).valid());
        assertThrows(IOException.class, () -> adapter.normalize(scan(contextProject, malformedOutput),
                artifacts(DependencyCheckAdapter.ID, malformed, malformedOutput)));

        Path unavailableOutput = Files.createDirectory(temporaryDirectory.resolve("unavailable"));
        Path unavailable = copyReport(getClass(), FIXTURE, "database-unavailable.json",
                unavailableOutput.resolve("report.json"), root);
        assertTrue(adapter.validate(artifacts(DependencyCheckAdapter.ID, unavailable, unavailableOutput)).errors()
                .contains("VULNERABILITY_DATABASE_UNAVAILABLE"));
        DependencyCheckAdapter noDatabase = new DependencyCheckAdapter(temporaryDirectory.resolve("empty-db"));
        assertEquals("VULNERABILITY_DATABASE_UNAVAILABLE",
                noDatabase.checkApplicability(contextProject,
                        tools(DependencyCheckAdapter.ID, Path.of(System.getProperty("java.home"), "bin", "java"),
                                DependencyCheckAdapter.TOOL_VERSION)).reasonCode());

        RawArtifactSet failed = new RawArtifactSet(DependencyCheckAdapter.ID, Map.of("report", clean),
                execution(cleanOutput, ExecutionResult.Status.FAILED, 13));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void realMacJdk17FindingSmokeWhenExecutableAndDatabaseAreProvided() throws Exception {
        String executable = System.getProperty("audit.dependency-check.executable", "");
        String dataValue = System.getProperty("audit.dependency-check.data", "");
        Assumptions.assumeTrue(!executable.isBlank() && !dataValue.isBlank());
        assertEquals("17", System.getProperty("java.specification.version"));
        Path data = Path.of(dataValue).toAbsolutePath().normalize();
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        createLog4jJar(root.resolve("target/log4j-core-2.14.1.jar"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        DependencyCheckAdapter adapter = new DependencyCheckAdapter(data);
        var context = scan(project(root, "supply-fixture"), output);
        ExecutionResult process = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(DependencyCheckAdapter.ID, Path.of(executable),
                        DependencyCheckAdapter.TOOL_VERSION)), CancellationToken.NONE);
        Path report = output.resolve("dependency-check-report.json");
        var result = adapter.normalize(context, new RawArtifactSet(DependencyCheckAdapter.ID,
                Map.of("report", report), process));
        assertEquals(ExecutionResult.Status.SUCCEEDED, process.status());
        var log4Shell = result.findings().stream().filter(finding ->
                finding.identifiers().cve().contains("CVE-2021-44228")).findFirst().orElseThrow();
        assertEquals("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", log4Shell.component().purl());
        assertEquals("2.14.1", log4Shell.component().version());
        assertFalse(log4Shell.component().dependencyPath().isEmpty());
        assertFalse(log4Shell.evidence().get(0).properties().get("databaseEvidence").toString().isBlank());
    }

    private Path initializedDatabase(Path directory) throws IOException {
        Files.createDirectories(directory);
        Files.writeString(directory.resolve("odc.mv.db"), "fixture-database-sentinel");
        return directory;
    }

    private void createLog4jJar(Path target) throws IOException {
        Files.createDirectories(target.getParent());
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().putValue("Implementation-Title", "Apache Log4j Core");
        manifest.getMainAttributes().putValue("Implementation-Vendor", "Apache Software Foundation");
        manifest.getMainAttributes().putValue("Implementation-Version", "2.14.1");
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(target), manifest)) {
            jar.putNextEntry(new JarEntry("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.xml"));
            jar.write(("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    + "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n"
                    + "  <modelVersion>4.0.0</modelVersion>\n"
                    + "  <groupId>org.apache.logging.log4j</groupId>\n"
                    + "  <artifactId>log4j-core</artifactId>\n"
                    + "  <version>2.14.1</version>\n"
                    + "  <name>Apache Log4j Core</name>\n"
                    + "</project>\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            jar.closeEntry();
            jar.putNextEntry(new JarEntry("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"));
            jar.write("groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            jar.closeEntry();
        }
    }
}
