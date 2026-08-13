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
        assertEquals(Integer.toString(PmdCpdAdapter.MINIMUM_TOKENS),
                specification.command().get(specification.command().indexOf("--minimum-tokens") + 1));
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
        assertEquals("DUPLICATION", finding.ruleFamily());
        assertEquals(PmdCpdAdapter.MINIMUM_TOKENS,
                finding.evidence().get(0).properties().get("minimumTokens"));
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
        String duplicated = duplicatedSource("DuplicateA");
        Files.writeString(root.resolve("src/main/java/example/DuplicateA.java"), duplicated);
        Files.writeString(root.resolve("src/main/java/example/DuplicateB.java"), duplicatedSource("DuplicateB"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        PmdCpdAdapter adapter = new PmdCpdAdapter(home); var context = scan(project(root, "cpd-fixture"), output);
        ExecutionResult process = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(PmdCpdAdapter.ID, java, PmdCpdAdapter.TOOL_VERSION)), CancellationToken.NONE);
        var normalized = adapter.normalize(context, new RawArtifactSet(PmdCpdAdapter.ID,
                Map.of("report", output.resolve("report.xml")), process));
        assertEquals(ExecutionResult.Status.SUCCEEDED, process.status());
        assertFalse(normalized.findings().isEmpty());
    }

    private String duplicatedSource(String className) {
        return ("""
                package example;
                public final class %s {
                    int calculate(int[] values) {
                        int total = 0;
                        for (int value : values) {
                            if (value > 100) { total += value * 2; }
                            else if (value > 90) { total += value + 90; }
                            else if (value > 80) { total += value + 80; }
                            else if (value > 70) { total += value + 70; }
                            else if (value > 60) { total += value + 60; }
                            else if (value > 50) { total += value + 50; }
                            else if (value > 40) { total += value + 40; }
                            else if (value > 30) { total += value + 30; }
                            else if (value > 20) { total += value + 20; }
                            else if (value > 10) { total += value + 10; }
                            else if (value > 0) { total += value; }
                            else { total -= value; }
                        }
                        return total;
                    }
                }
                """).formatted(className);
    }
}
