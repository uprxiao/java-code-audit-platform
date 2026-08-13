package io.github.uprxiao.audit.adapter.gitleaks;

import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.artifacts;
import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.copyProject;
import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.copyReport;
import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.execution;
import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.project;
import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.scan;
import static io.github.uprxiao.audit.adapter.testing.AdapterTestFixtures.tools;
import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertDescriptorContract;
import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertSafeExecutionSpec;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

class GitleaksAdapterTest {

    private static final String FIXTURE = "/fixtures/gitleaks/8.30.1";

    @TempDir Path temporaryDirectory;

    @Test
    void preparesSafeRedactedDirectoryScan() throws Exception {
        Path rules = Files.writeString(temporaryDirectory.resolve("gitleaks.toml"), "title='test'\n");
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = temporaryDirectory.resolve("task/raw/gitleaks");
        GitleaksAdapter adapter = new GitleaksAdapter(rules);
        var context = scan(project(root, "gitleaks-fixture"), output);
        var executable = Path.of(System.getProperty("java.home"), "bin", "java");

        assertDescriptorContract(adapter);
        assertEquals(io.github.uprxiao.audit.scanner.Applicability.Status.APPLICABLE,
                adapter.checkApplicability(context.project(), tools(GitleaksAdapter.ID, executable, GitleaksAdapter.TOOL_VERSION)).status());
        assertEquals("TOOL_VERSION_MISMATCH", adapter.checkApplicability(context.project(),
                tools(GitleaksAdapter.ID, executable, "8.0.0")).reasonCode());
        var specification = adapter.prepare(context, tools(GitleaksAdapter.ID, executable, GitleaksAdapter.TOOL_VERSION));
        assertSafeExecutionSpec(specification, temporaryDirectory.resolve("task"));
        assertTrue(specification.command().contains("--redact=100"));
        assertFalse(specification.command().contains("sh"));
    }

    @Test
    void normalizesSecretWithoutRetainingSecretText() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        Path output = Files.createDirectories(temporaryDirectory.resolve("output"));
        Path report = copyReport(getClass(), FIXTURE, "findings.json", output.resolve("report.json"), root);
        var result = new GitleaksAdapter(temporaryDirectory.resolve("rules"))
                .normalize(scan(project(root, "gitleaks-fixture"), output), artifacts(GitleaksAdapter.ID, report, output));

        assertEquals(1, result.findings().size());
        var finding = result.findings().get(0);
        assertEquals(IssueCategory.SECRET_EXPOSURE, finding.category());
        assertEquals("SECRET", finding.ruleFamily());
        assertTrue(finding.snippet().redacted());
        assertFalse(finding.toString().contains("AUDIT_SECRET"));
        assertEquals(EngineStatus.SUCCEEDED, result.coverage().status());
    }

    @Test
    void cleanPartialMalformedFailedAndUnredactedAreDistinct() throws Exception {
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("project"));
        var contextProject = project(root, "gitleaks-fixture");
        GitleaksAdapter adapter = new GitleaksAdapter(temporaryDirectory.resolve("rules"));

        Path cleanOutput = Files.createDirectory(temporaryDirectory.resolve("clean"));
        Path clean = copyReport(getClass(), FIXTURE, "clean.json", cleanOutput.resolve("report.json"), root);
        assertTrue(adapter.normalize(scan(contextProject, cleanOutput), artifacts(GitleaksAdapter.ID, clean, cleanOutput)).findings().isEmpty());

        Path partialOutput = Files.createDirectory(temporaryDirectory.resolve("partial"));
        Path partial = copyReport(getClass(), FIXTURE, "partial.json", partialOutput.resolve("report.json"), root);
        assertEquals(EngineStatus.PARTIAL,
                adapter.normalize(scan(contextProject, partialOutput), artifacts(GitleaksAdapter.ID, partial, partialOutput)).coverage().status());

        Path malformedOutput = Files.createDirectory(temporaryDirectory.resolve("malformed"));
        Path malformed = copyReport(getClass(), FIXTURE, "malformed.json", malformedOutput.resolve("report.json"), root);
        assertFalse(adapter.validate(artifacts(GitleaksAdapter.ID, malformed, malformedOutput)).valid());
        assertThrows(IOException.class,
                () -> adapter.normalize(scan(contextProject, malformedOutput), artifacts(GitleaksAdapter.ID, malformed, malformedOutput)));

        RawArtifactSet failed = new RawArtifactSet(GitleaksAdapter.ID, Map.of("report", clean),
                execution(cleanOutput, ExecutionResult.Status.FAILED, 2));
        assertTrue(adapter.validate(failed).errors().contains("EXECUTION_FAILED"));

        Path unsafe = Files.writeString(temporaryDirectory.resolve("unsafe.json"),
                "[{\"RuleID\":\"x\",\"File\":\"x\",\"StartLine\":1,\"Secret\":\"cleartext\"}]");
        assertTrue(adapter.validate(artifacts(GitleaksAdapter.ID, unsafe, cleanOutput)).errors()
                .contains("REPORT_CONTAINS_UNREDACTED_SECRET"));
    }

    @Test
    void realGitleaksSmokeWhenExecutableIsProvided() throws Exception {
        String configured = System.getProperty("audit.gitleaks.executable", "");
        Assumptions.assumeTrue(!configured.isBlank());
        Path executable = Path.of(configured).toAbsolutePath().normalize();
        Path rules = Path.of(System.getProperty("audit.gitleaks.rules")).toAbsolutePath().normalize();
        Path root = copyProject(getClass(), FIXTURE, temporaryDirectory.resolve("real-project"));
        String canary = "glpat-" + "1234567890abcdefghij";
        Files.writeString(root.resolve("src/main/java/example/Secrets.java"),
                "package example; final class Secrets { static final String TOKEN = \"" + canary + "\"; }\n");
        Path output = Files.createDirectories(temporaryDirectory.resolve("real-output"));
        GitleaksAdapter adapter = new GitleaksAdapter(rules);
        var context = scan(project(root, "gitleaks-fixture"), output);
        var specification = adapter.prepare(context, tools(GitleaksAdapter.ID, executable, GitleaksAdapter.TOOL_VERSION));
        ExecutionResult process = new LocalProcessExecutionBackend().execute(specification, CancellationToken.NONE);
        RawArtifactSet raw = new RawArtifactSet(GitleaksAdapter.ID, Map.of("report", output.resolve("report.json")), process);
        var normalized = adapter.normalize(context, raw);

        assertEquals(ExecutionResult.Status.SUCCEEDED, process.status());
        assertFalse(normalized.findings().isEmpty());
        assertFalse(Files.readString(output.resolve("report.json")).contains(canary));
    }
}
