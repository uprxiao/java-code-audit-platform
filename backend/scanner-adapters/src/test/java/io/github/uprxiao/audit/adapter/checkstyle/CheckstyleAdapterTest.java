package io.github.uprxiao.audit.adapter.checkstyle;

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

class CheckstyleAdapterTest {
    private static final String FIXTURE = "/fixtures/checkstyle/12.3.1";
    @TempDir Path temporaryDirectory;

    @Test
    void preparesDeterministicXmlCommandWithoutShell() throws Exception {
        Path config = Files.writeString(temporaryDirectory.resolve("checkstyle.xml"), "<module name=\"Checker\"/>\n");
        Path jar = Files.writeString(temporaryDirectory.resolve("checkstyle.jar"), "fixture");
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        CheckstyleAdapter adapter = new CheckstyleAdapter(config, jar);
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");
        var specification = adapter.prepare(scan(project(root, "checkstyle-fixture"), temporaryDirectory.resolve("task/raw/checkstyle")),
                tools(CheckstyleAdapter.ID, java, CheckstyleAdapter.TOOL_VERSION));
        assertDescriptorContract(adapter); assertSafeExecutionSpec(specification, temporaryDirectory.resolve("task"));
        assertTrue(specification.command().contains("-Duser.language=en"));
        assertTrue(specification.command().contains("-Dfile.encoding=UTF-8"));
        assertTrue(specification.command().contains(root.resolve("src/main/java").toString()));
        assertFalse(specification.command().contains(root.toString()));
        assertTrue(specification.command().contains("xml"));
        assertFalse(specification.command().contains("sh"));
    }

    @Test
    void goldenStyleFindingKeepsRuleAndSnippet() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("output"));
        Path report = copyReport(getClass(), FIXTURE, "findings.xml", output.resolve("report.xml"), root);
        var result = new CheckstyleAdapter(Path.of("config"), Path.of("jar"))
                .normalize(scan(project(root, "checkstyle-fixture"), output), artifacts(CheckstyleAdapter.ID, report, output));
        assertEquals(1, result.findings().size());
        var finding = result.findings().get(0);
        assertEquals(IssueCategory.CODE_STYLE, finding.category());
        assertEquals("AVOID_STAR_IMPORT", finding.ruleFamily());
        assertTrue(finding.snippet().text().contains("java.util.*"));
    }

    @Test
    void cleanPartialMalformedAndFailedAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        var contextProject = project(root, "checkstyle-fixture");
        CheckstyleAdapter adapter = new CheckstyleAdapter(Path.of("config"), Path.of("jar"));
        Path cleanOut = Files.createDirectory(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.xml", cleanOut.resolve("report.xml"), root);
        assertTrue(adapter.normalize(scan(contextProject, cleanOut), artifacts(CheckstyleAdapter.ID, clean, cleanOut)).findings().isEmpty());
        Path partialOut = Files.createDirectory(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.xml", partialOut.resolve("report.xml"), root);
        assertEquals(EngineStatus.PARTIAL, adapter.normalize(scan(contextProject, partialOut),
                artifacts(CheckstyleAdapter.ID, partial, partialOut)).coverage().status());
        Path badOut = Files.createDirectory(temporaryDirectory.resolve("bad"));
        Path bad = copyReport(getClass(), FIXTURE, "malformed.xml", badOut.resolve("report.xml"), root);
        assertFalse(adapter.validate(artifacts(CheckstyleAdapter.ID, bad, badOut)).valid());
        assertThrows(IOException.class, () -> adapter.normalize(scan(contextProject, badOut), artifacts(CheckstyleAdapter.ID, bad, badOut)));
        RawArtifactSet failed = new RawArtifactSet(CheckstyleAdapter.ID, Map.of("report", clean),
                execution(cleanOut, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void realCheckstyleSmokeWhenJarIsProvided() throws Exception {
        String jarProperty = System.getProperty("audit.checkstyle.jar", ""); Assumptions.assumeTrue(!jarProperty.isBlank());
        Path jar = Path.of(jarProperty).toAbsolutePath().normalize();
        Path config = Path.of(System.getProperty("audit.checkstyle.rules")).toAbsolutePath().normalize();
        Path java = Path.of(System.getProperty("audit.checkstyle.java", System.getProperty("java.home") + "/bin/java"));
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        CheckstyleAdapter adapter = new CheckstyleAdapter(config, jar); var context = scan(project(root, "checkstyle-fixture"), output);
        ExecutionResult process = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(CheckstyleAdapter.ID, java, CheckstyleAdapter.TOOL_VERSION)), CancellationToken.NONE);
        var normalized = adapter.normalize(context, new RawArtifactSet(CheckstyleAdapter.ID,
                Map.of("report", output.resolve("report.xml")), process));
        assertEquals(ExecutionResult.Status.SUCCEEDED, process.status());
        assertTrue(normalized.findings().stream().anyMatch(finding -> finding.ruleFamily().equals("AVOID_STAR_IMPORT")));
        assertTrue(normalized.warnings().isEmpty());
    }
}
