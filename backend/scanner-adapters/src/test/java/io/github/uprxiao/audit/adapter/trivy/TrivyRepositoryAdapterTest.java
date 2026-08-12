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
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrivyRepositoryAdapterTest {
    private static final String FIXTURE = "/fixtures/trivy-repository/0.73.0";
    @TempDir Path temporaryDirectory;

    @Test
    void preparesBoundedRepositoryScanWithoutShell() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        TrivyRepositoryAdapter adapter = new TrivyRepositoryAdapter(temporaryDirectory.resolve("cache"));
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");
        var specification = adapter.prepare(scan(project(root, "trivy-fixture"), temporaryDirectory.resolve("task/raw/trivy-repository")),
                tools(TrivyRepositoryAdapter.ID, executable, TrivyRepositoryAdapter.TOOL_VERSION));
        assertDescriptorContract(adapter); assertSafeExecutionSpec(specification, temporaryDirectory.resolve("task"));
        assertTrue(specification.command().contains("misconfig,secret,license"));
        assertTrue(specification.command().contains("--cache-dir"));
        assertTrue(specification.command().contains("--offline-scan"));
        assertFalse(specification.command().contains("sh"));
    }

    @Test
    void goldenRepositoryFindingsSeparateConfigAndRedactedSecret() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("output"));
        Path report = copyReport(getClass(), FIXTURE, "findings.json", output.resolve("report.json"), root);
        var result = new TrivyRepositoryAdapter(temporaryDirectory.resolve("cache"))
                .normalize(scan(project(root, "trivy-fixture"), output), artifacts(TrivyRepositoryAdapter.ID, report, output));
        assertEquals(2, result.findings().size());
        assertTrue(result.findings().stream().anyMatch(finding -> finding.category() == IssueCategory.CONFIG_IAC_SECURITY));
        var secret = result.findings().stream().filter(finding -> finding.category() == IssueCategory.SECRET_EXPOSURE).findFirst().orElseThrow();
        assertTrue(secret.snippet().redacted());
        assertFalse(secret.toString().contains("ghp_"));
    }

    @Test
    void cleanPartialMalformedFailedAndUnredactedAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        var contextProject = project(root, "trivy-fixture");
        TrivyRepositoryAdapter adapter = new TrivyRepositoryAdapter(temporaryDirectory.resolve("cache"));
        Path cleanOut = Files.createDirectory(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.json", cleanOut.resolve("report.json"), root);
        assertTrue(adapter.normalize(scan(contextProject, cleanOut), artifacts(TrivyRepositoryAdapter.ID, clean, cleanOut)).findings().isEmpty());
        Path partialOut = Files.createDirectory(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.json", partialOut.resolve("report.json"), root);
        assertEquals(EngineStatus.PARTIAL, adapter.normalize(scan(contextProject, partialOut),
                artifacts(TrivyRepositoryAdapter.ID, partial, partialOut)).coverage().status());
        Path badOut = Files.createDirectory(temporaryDirectory.resolve("bad"));
        Path bad = copyReport(getClass(), FIXTURE, "malformed.json", badOut.resolve("report.json"), root);
        assertFalse(adapter.validate(artifacts(TrivyRepositoryAdapter.ID, bad, badOut)).valid());
        assertThrows(IOException.class, () -> adapter.normalize(scan(contextProject, badOut), artifacts(TrivyRepositoryAdapter.ID, bad, badOut)));
        RawArtifactSet failed = new RawArtifactSet(TrivyRepositoryAdapter.ID, Map.of("report", clean),
                execution(cleanOut, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));
        Path unsafe = Files.writeString(temporaryDirectory.resolve("unsafe.json"),
                "{\"Results\":[{\"Secrets\":[{\"Match\":\"cleartext\",\"Code\":{\"Lines\":[]}}]}]}");
        assertTrue(adapter.validate(artifacts(TrivyRepositoryAdapter.ID, unsafe, cleanOut)).errors()
                .contains("REPORT_CONTAINS_UNREDACTED_SECRET"));
    }

    @Test
    void realTrivySmokeWhenExecutableIsProvided() throws Exception {
        String configured = System.getProperty("audit.trivy.executable", ""); Assumptions.assumeTrue(!configured.isBlank());
        Path executable = Path.of(configured).toAbsolutePath().normalize();
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        TrivyRepositoryAdapter adapter = new TrivyRepositoryAdapter(temporaryDirectory.resolve("trivy-cache"));
        var context = scan(project(root, "trivy-fixture"), output);
        ExecutionResult process = new LocalProcessExecutionBackend().execute(
                adapter.prepare(context, tools(TrivyRepositoryAdapter.ID, executable, TrivyRepositoryAdapter.TOOL_VERSION)), CancellationToken.NONE);
        var normalized = adapter.normalize(context, new RawArtifactSet(TrivyRepositoryAdapter.ID,
                Map.of("report", output.resolve("report.json")), process));
        assertEquals(ExecutionResult.Status.SUCCEEDED, process.status());
        assertTrue(normalized.findings().stream().anyMatch(finding -> finding.category() == IssueCategory.CONFIG_IAC_SECURITY));
        assertTrue(normalized.findings().stream().anyMatch(finding -> finding.category() == IssueCategory.SECRET_EXPOSURE));
        assertFalse(Files.readString(output.resolve("report.json")).contains("ghp_abcdefghijklmnopqrstuvwxyz1234567890AB"));
    }
}
