package io.github.uprxiao.audit.adapter.pmd;

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

class PmdAdapterTest {
    private static final String FIXTURE = "/fixtures/pmd/7.26.0";
    @TempDir Path temporaryDirectory;

    @Test
    void preparesJava17PmdWithoutShell() throws Exception {
        Path rules = Files.writeString(temporaryDirectory.resolve("rules.xml"), "<ruleset/>\n");
        Path home = temporaryDirectory.resolve("pmd");
        Files.createDirectories(home.resolve("lib"));
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        PmdAdapter adapter = new PmdAdapter(rules, home);
        var java = Path.of(System.getProperty("java.home"), "bin", "java");
        var specification = adapter.prepare(scan(project(root, "pmd-fixture"), temporaryDirectory.resolve("task/raw/pmd")),
                tools(PmdAdapter.ID, java, PmdAdapter.TOOL_VERSION));
        assertDescriptorContract(adapter);
        assertSafeExecutionSpec(specification, temporaryDirectory.resolve("task"));
        assertTrue(specification.command().contains("java-17"));
        assertTrue(specification.command().contains("--no-fail-on-error"));
        assertFalse(specification.command().contains("sh"));
    }

    @Test
    void goldenFindingKeepsRuleAndLocation() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("output"));
        Path report = copyReport(getClass(), FIXTURE, "findings.json", output.resolve("report.json"), root);
        var result = new PmdAdapter(Path.of("rules"), Path.of("pmd"))
                .normalize(scan(project(root, "pmd-fixture"), output), artifacts(PmdAdapter.ID, report, output));
        assertEquals(1, result.findings().size());
        var finding = result.findings().get(0);
        assertEquals(IssueCategory.RESOURCE_PERFORMANCE, finding.category());
        assertEquals("CLOSE_RESOURCE", finding.ruleFamily());
        assertEquals(10, finding.location().startLine());
        assertEquals("CloseResource", finding.evidence().get(0).ruleId());
    }

    @Test
    void cleanPartialMalformedAndFailedAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        var contextProject = project(root, "pmd-fixture");
        PmdAdapter adapter = new PmdAdapter(Path.of("rules"), Path.of("pmd"));
        Path cleanOut = Files.createDirectory(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.json", cleanOut.resolve("report.json"), root);
        assertTrue(adapter.normalize(scan(contextProject, cleanOut), artifacts(PmdAdapter.ID, clean, cleanOut)).findings().isEmpty());
        Path partialOut = Files.createDirectory(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.json", partialOut.resolve("report.json"), root);
        assertEquals(EngineStatus.PARTIAL, adapter.normalize(scan(contextProject, partialOut),
                artifacts(PmdAdapter.ID, partial, partialOut)).coverage().status());
        Path malformedOut = Files.createDirectory(temporaryDirectory.resolve("malformed"));
        Path malformed = copyReport(getClass(), FIXTURE, "malformed.json", malformedOut.resolve("report.json"), root);
        assertFalse(adapter.validate(artifacts(PmdAdapter.ID, malformed, malformedOut)).valid());
        assertThrows(IOException.class, () -> adapter.normalize(scan(contextProject, malformedOut),
                artifacts(PmdAdapter.ID, malformed, malformedOut)));
        RawArtifactSet failed = new RawArtifactSet(PmdAdapter.ID, Map.of("report", clean),
                execution(cleanOut, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void realPmdSmokeWhenToolHomeIsProvided() throws Exception {
        String homeProperty = System.getProperty("audit.pmd.home", "");
        Assumptions.assumeTrue(!homeProperty.isBlank());
        Path home = Path.of(homeProperty).toAbsolutePath().normalize();
        Path rules = Path.of(System.getProperty("audit.pmd.rules")).toAbsolutePath().normalize();
        Path java = Path.of(System.getProperty("audit.pmd.java", System.getProperty("java.home") + "/bin/java"));
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        PmdAdapter adapter = new PmdAdapter(rules, home);
        var context = scan(project(root, "pmd-fixture"), output);
        ExecutionResult process = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(PmdAdapter.ID, java, PmdAdapter.TOOL_VERSION)), CancellationToken.NONE);
        var normalized = adapter.normalize(context, new RawArtifactSet(PmdAdapter.ID,
                Map.of("report", output.resolve("report.json")), process));
        assertEquals(ExecutionResult.Status.SUCCEEDED, process.status());
        assertTrue(normalized.findings().stream().anyMatch(finding -> finding.ruleFamily().equals("CLOSE_RESOURCE")));
    }
}
