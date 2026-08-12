package io.github.uprxiao.audit.adapter.spotbugs;

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

class SpotBugsAdapterTest {
    private static final String FIXTURE = "/fixtures/spotbugs/4.9.3";
    @TempDir Path temporaryDirectory;

    @Test
    void preparesFixedJavaCommandAgainstCompiledClasses() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Files.createDirectories(root.resolve("target/classes"));
        Path dependency = Files.writeString(temporaryDirectory.resolve("provided-api.jar"), "fixture");
        Files.writeString(root.resolve("target/audit-runtime-classpath.txt"), dependency.toString());
        Path home = fakeHome();
        Path plugin = Files.writeString(temporaryDirectory.resolve("findsecbugs.jar"), "fixture");
        Path filter = Files.writeString(temporaryDirectory.resolve("exclude.xml"), "<FindBugsFilter/>");
        SpotBugsAdapter adapter = new SpotBugsAdapter(home, plugin, filter);
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");
        var spec = adapter.prepare(scan(project(root, "spotbugs-fixture"), temporaryDirectory.resolve("task/raw/spotbugs")),
                tools(SpotBugsAdapter.ID, java, SpotBugsAdapter.TOOL_VERSION));
        assertDescriptorContract(adapter);
        assertSafeExecutionSpec(spec, temporaryDirectory.resolve("task"));
        assertTrue(spec.command().contains("edu.umd.cs.findbugs.LaunchAppropriateUI"));
        assertTrue(spec.command().contains("-pluginList"));
        assertTrue(spec.command().contains("-xml:withMessages"));
        assertTrue(spec.command().get(spec.command().indexOf("-auxclasspath") + 1)
                .contains(dependency.toString()));
        assertFalse(spec.command().contains("sh"));
    }

    @Test
    void goldenCleanFindingPartialMalformedAndProcessFailureAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        SpotBugsAdapter adapter = new SpotBugsAdapter(Path.of("home"), Path.of("plugin"), null);
        Path findingOut = Files.createDirectories(temporaryDirectory.resolve("finding"));
        Path findingReport = copyReport(getClass(), FIXTURE, "findings.xml", findingOut.resolve("report.xml"), root);
        var normalized = adapter.normalize(scan(project(root, "spotbugs-fixture"), findingOut),
                artifacts(SpotBugsAdapter.ID, findingReport, findingOut));
        assertEquals(1, normalized.findings().size());
        var finding = normalized.findings().get(0);
        assertEquals(IssueCategory.CORRECTNESS, finding.category());
        assertEquals("NULL_DEREFERENCE", finding.ruleFamily());
        assertEquals("src/main/java/example/SpotBugsIssue.java", finding.location().path());
        assertTrue(finding.fingerprint().matches("sha256:[0-9a-f]{64}"));
        assertEquals("java-audit-severity-v1", finding.evidence().get(0).properties().get("severityMappingId"));

        Path cleanOut = Files.createDirectories(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.xml", cleanOut.resolve("report.xml"), root);
        assertTrue(adapter.normalize(scan(project(root, "spotbugs-fixture"), cleanOut),
                artifacts(SpotBugsAdapter.ID, clean, cleanOut)).findings().isEmpty());

        Path partialOut = Files.createDirectories(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.xml", partialOut.resolve("report.xml"), root);
        assertEquals(EngineStatus.PARTIAL, adapter.normalize(scan(project(root, "spotbugs-fixture"), partialOut),
                artifacts(SpotBugsAdapter.ID, partial, partialOut)).coverage().status());

        Path badOut = Files.createDirectories(temporaryDirectory.resolve("bad"));
        Path bad = copyReport(getClass(), FIXTURE, "malformed.xml", badOut.resolve("report.xml"), root);
        assertFalse(adapter.validate(artifacts(SpotBugsAdapter.ID, bad, badOut)).valid());
        assertThrows(IOException.class, () -> adapter.normalize(scan(project(root, "spotbugs-fixture"), badOut),
                artifacts(SpotBugsAdapter.ID, bad, badOut)));

        RawArtifactSet failed = new RawArtifactSet(SpotBugsAdapter.ID, Map.of("report", clean),
                execution(cleanOut, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void realMacJdk17SmokeWhenPackIsProvided() throws Exception {
        String homeProperty = System.getProperty("audit.spotbugs.home", "");
        Assumptions.assumeTrue(!homeProperty.isBlank());
        Path home = Path.of(homeProperty).toAbsolutePath().normalize();
        Path plugin = Path.of(System.getProperty("audit.findsecbugs.plugin")).toAbsolutePath().normalize();
        Path filter = Path.of(System.getProperty("audit.spotbugs.exclude")).toAbsolutePath().normalize();
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        compile(root);
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");
        SpotBugsAdapter adapter = new SpotBugsAdapter(home, plugin, filter);
        var context = scan(project(root, "spotbugs-fixture"), output);
        ExecutionResult execution = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(SpotBugsAdapter.ID, java, SpotBugsAdapter.TOOL_VERSION)), CancellationToken.NONE);
        assertEquals(ExecutionResult.Status.SUCCEEDED, execution.status(), () -> read(execution.stderr()));
        var result = adapter.normalize(context, new RawArtifactSet(SpotBugsAdapter.ID,
                Map.of("report", output.resolve("report.xml")), execution));
        assertTrue(result.findings().stream().anyMatch(value -> value.ruleFamily().equals("NULL_DEREFERENCE")),
                () -> "actual=" + result.findings());
    }

    private Path fakeHome() throws Exception {
        Path lib = Files.createDirectories(temporaryDirectory.resolve("fake-home/lib"));
        Files.writeString(lib.resolve("spotbugs.jar"), "fixture");
        return lib.getParent();
    }

    static void compile(Path root) throws Exception {
        Process process = new ProcessBuilder(System.getProperty("audit.standard.maven", "/opt/homebrew/bin/mvn"),
                "--batch-mode", "--no-transfer-progress", "--file", root.resolve("pom.xml").toString(), "package")
                .inheritIO().start();
        assertEquals(0, process.waitFor());
    }

    private String read(Path path) {
        try { return Files.readString(path); } catch (IOException exception) { return exception.toString(); }
    }
}
