package io.github.uprxiao.audit.adapter.spotbugs;

import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.*;
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

class FindSecBugsAdapterTest {
    private static final String FIXTURE = "/fixtures/findsecbugs/1.14.0";
    @TempDir Path temporaryDirectory;

    @Test
    void goldenCleanFindingPartialMalformedAndProcessFailureAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        FindSecBugsAdapter adapter = new FindSecBugsAdapter(Path.of("home"), Path.of("plugin"), null);
        Path findingOut = Files.createDirectories(temporaryDirectory.resolve("finding"));
        Path report = copyReport(getClass(), FIXTURE, "findings.xml", findingOut.resolve("report.xml"), root);
        var normalized = adapter.normalize(scan(project(root, "findsecbugs-fixture"), findingOut),
                artifacts(FindSecBugsAdapter.ID, report, findingOut));
        assertEquals(1, normalized.findings().size());
        var finding = normalized.findings().get(0);
        assertEquals(IssueCategory.WEB_SECURITY, finding.category());
        assertEquals("SQL_INJECTION", finding.ruleFamily());
        assertEquals("CWE-89", finding.identifiers().cwe().get(0));
        assertEquals("src/main/java/example/SqlIssue.java", finding.location().path());
        assertTrue(finding.fingerprint().matches("sha256:[0-9a-f]{64}"));

        Path cleanOut = Files.createDirectories(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.xml", cleanOut.resolve("report.xml"), root);
        assertTrue(adapter.normalize(scan(project(root, "findsecbugs-fixture"), cleanOut),
                artifacts(FindSecBugsAdapter.ID, clean, cleanOut)).findings().isEmpty());
        Path partialOut = Files.createDirectories(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.xml", partialOut.resolve("report.xml"), root);
        assertEquals(EngineStatus.PARTIAL, adapter.normalize(scan(project(root, "findsecbugs-fixture"), partialOut),
                artifacts(FindSecBugsAdapter.ID, partial, partialOut)).coverage().status());
        Path badOut = Files.createDirectories(temporaryDirectory.resolve("bad"));
        Path bad = copyReport(getClass(), FIXTURE, "malformed.xml", badOut.resolve("report.xml"), root);
        assertFalse(adapter.validate(artifacts(FindSecBugsAdapter.ID, bad, badOut)).valid());
        assertThrows(IOException.class, () -> adapter.normalize(scan(project(root, "findsecbugs-fixture"), badOut),
                artifacts(FindSecBugsAdapter.ID, bad, badOut)));
        RawArtifactSet failed = new RawArtifactSet(FindSecBugsAdapter.ID, Map.of("report", clean),
                execution(cleanOut, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void realPluginSmokeFindsSqlInjectionWhenPackIsProvided() throws Exception {
        String homeProperty = System.getProperty("audit.spotbugs.home", "");
        Assumptions.assumeTrue(!homeProperty.isBlank());
        Path home = Path.of(homeProperty).toAbsolutePath().normalize();
        Path plugin = Path.of(System.getProperty("audit.findsecbugs.plugin")).toAbsolutePath().normalize();
        Path filter = Path.of(System.getProperty("audit.spotbugs.exclude")).toAbsolutePath().normalize();
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        SpotBugsAdapterTest.compile(root);
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        Path java = Path.of(System.getProperty("java.home"), "bin", "java");
        FindSecBugsAdapter adapter = new FindSecBugsAdapter(home, plugin, filter);
        var context = scan(project(root, "findsecbugs-fixture"), output);
        ExecutionResult execution = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(FindSecBugsAdapter.ID, java, FindSecBugsAdapter.TOOL_VERSION)), CancellationToken.NONE);
        assertEquals(ExecutionResult.Status.SUCCEEDED, execution.status());
        var result = adapter.normalize(context, new RawArtifactSet(FindSecBugsAdapter.ID,
                Map.of("report", output.resolve("report.xml")), execution));
        assertTrue(result.findings().stream().anyMatch(value -> value.ruleFamily().equals("SQL_INJECTION")),
                () -> "actual=" + result.findings());
    }
}
