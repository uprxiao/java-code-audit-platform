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

class PmdCpdAdapterTest {
    private static final String FIXTURE = "/fixtures/pmd-cpd/7.26.0";
    @TempDir Path temporaryDirectory;

    @Test
    void preparesCpdXmlCommandWithoutShell() throws Exception {
        Path home = temporaryDirectory.resolve("pmd"); Files.createDirectories(home.resolve("lib"));
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        PmdCpdAdapter adapter = new PmdCpdAdapter(home);
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");
        var specification = adapter.prepare(scan(project(root, "cpd-fixture"), temporaryDirectory.resolve("task/raw/pmd-cpd")),
                tools(PmdCpdAdapter.ID, java, PmdCpdAdapter.TOOL_VERSION));
        assertDescriptorContract(adapter); assertSafeExecutionSpec(specification, temporaryDirectory.resolve("task"));
        assertTrue(specification.command().contains("--minimum-tokens"));
        assertFalse(specification.command().contains("sh"));
    }

    @Test
    void goldenDuplicationKeepsAllOccurrencesAsEvidence() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("output"));
        Path report = copyReport(getClass(), FIXTURE, "findings.xml", output.resolve("report.xml"), root);
        var result = new PmdCpdAdapter(Path.of("pmd")).normalize(scan(project(root, "cpd-fixture"), output),
                artifacts(PmdCpdAdapter.ID, report, output));
        assertEquals(1, result.findings().size());
        var finding = result.findings().get(0);
        assertEquals(IssueCategory.DUPLICATION, finding.category());
        assertEquals("DUPLICATE_CODE", finding.ruleFamily());
        assertEquals(2, ((java.util.List<?>) finding.evidence().get(0).properties().get("occurrences")).size());
    }

    @Test
    void cleanPartialMalformedAndFailedAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        var contextProject = project(root, "cpd-fixture"); PmdCpdAdapter adapter = new PmdCpdAdapter(Path.of("pmd"));
        Path cleanOut = Files.createDirectory(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.xml", cleanOut.resolve("report.xml"), root);
        assertTrue(adapter.normalize(scan(contextProject, cleanOut), artifacts(PmdCpdAdapter.ID, clean, cleanOut)).findings().isEmpty());
        Path partialOut = Files.createDirectory(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.xml", partialOut.resolve("report.xml"), root);
        assertEquals(EngineStatus.PARTIAL, adapter.normalize(scan(contextProject, partialOut),
                artifacts(PmdCpdAdapter.ID, partial, partialOut)).coverage().status());
        Path badOut = Files.createDirectory(temporaryDirectory.resolve("bad"));
        Path bad = copyReport(getClass(), FIXTURE, "malformed.xml", badOut.resolve("report.xml"), root);
        assertFalse(adapter.validate(artifacts(PmdCpdAdapter.ID, bad, badOut)).valid());
        assertThrows(IOException.class, () -> adapter.normalize(scan(contextProject, badOut), artifacts(PmdCpdAdapter.ID, bad, badOut)));
        RawArtifactSet failed = new RawArtifactSet(PmdCpdAdapter.ID, Map.of("report", clean), execution(cleanOut, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void realCpdSmokeWhenToolHomeIsProvided() throws Exception {
        String homeProperty = System.getProperty("audit.pmd.home", ""); Assumptions.assumeTrue(!homeProperty.isBlank());
        Path home = Path.of(homeProperty).toAbsolutePath().normalize();
        Path java = Path.of(System.getProperty("audit.pmd.java", System.getProperty("java.home") + "/bin/java"));
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        PmdCpdAdapter adapter = new PmdCpdAdapter(home); var context = scan(project(root, "cpd-fixture"), output);
        ExecutionResult process = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(PmdCpdAdapter.ID, java, PmdCpdAdapter.TOOL_VERSION)), CancellationToken.NONE);
        var normalized = adapter.normalize(context, new RawArtifactSet(PmdCpdAdapter.ID,
                Map.of("report", output.resolve("report.xml")), process));
        assertEquals(ExecutionResult.Status.SUCCEEDED, process.status());
        assertFalse(normalized.findings().isEmpty());
    }
}
