package io.github.uprxiao.audit.adapter.codeql;

import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertDescriptorContract;
import static io.github.uprxiao.audit.scanner.testing.ScannerAdapterTestKit.assertSafeExecutionSpec;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.uprxiao.audit.finding.DataFlowNode;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.SourceType;
import io.github.uprxiao.audit.intake.MavenModule;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.intake.ProjectManifest;
import io.github.uprxiao.audit.intake.SourceDescriptor;
import io.github.uprxiao.audit.process.LocalProcessExecutionBackend;
import io.github.uprxiao.audit.scanner.Applicability;
import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.CancellationToken;
import io.github.uprxiao.audit.scanner.ExecutionBackend;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CodeqlAdapterTest {

    private static final String FIXTURE = "/fixtures/codeql/2.26.2-java-queries-1.11.7/";

    @TempDir
    Path temporaryDirectory;

    @Test
    void contractUsesFourSafeShellFreePinnedPhases() throws Exception {
        Path suite = createPinnedQuerySuite();
        Path projectRoot = copyProject(temporaryDirectory.resolve("contract-project"));
        ProjectContext project = project(projectRoot);
        Path output = temporaryDirectory.resolve("task/raw/codeql");
        ScanContext scan = scan(project, output);
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");
        ToolContext tools = tools(executable, CodeqlAdapter.CLI_VERSION);
        CodeqlAdapter adapter = new CodeqlAdapter(suite);

        assertDescriptorContract(adapter);
        assertEquals(Applicability.Status.APPLICABLE, adapter.checkApplicability(project, tools).status());
        ExecutionSpec initialization = adapter.prepareDatabaseInitialization(scan, tools);
        assertSafeExecutionSpec(initialization, temporaryDirectory.resolve("task"));
        assertTrue(initialization.command().contains("--build-mode=manual"));
        assertFalse(initialization.command().stream().anyMatch(argument -> argument.startsWith("--command")));

        Files.createDirectories(adapter.databaseDirectory(scan));
        ExecutionSpec trace = adapter.prepareBuildTrace(scan, tools);
        assertSafeExecutionSpec(trace, temporaryDirectory.resolve("task"));
        assertTrue(trace.command().contains("trace-command"));
        assertTrue(trace.command().contains("clean"));
        assertTrue(trace.command().contains("package"));
        assertTrue(trace.command().contains("--"));
        assertFalse(trace.command().stream().anyMatch(argument -> argument.startsWith("--command")));
        ExecutionSpec finalization = adapter.prepareDatabaseFinalization(scan, tools);
        assertSafeExecutionSpec(finalization, temporaryDirectory.resolve("task"));
        assertTrue(finalization.command().contains("finalize"));
        ExecutionSpec analysis = adapter.prepareAnalysis(scan, tools);
        assertSafeExecutionSpec(analysis, temporaryDirectory.resolve("task"));
        assertTrue(analysis.command().contains("--format=sarifv2.1.0"));
        assertTrue(analysis.command().contains("--no-download"));
        assertTrue(analysis.command().contains(suite.toString()));
    }

    @Test
    void missingAndWrongVersionToolsAreExplicitlyUnavailable() throws Exception {
        Path suite = createPinnedQuerySuite();
        ProjectContext project = project(copyProject(temporaryDirectory.resolve("unavailable-project")));
        CodeqlAdapter adapter = new CodeqlAdapter(suite);
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");

        Applicability missing = adapter.checkApplicability(project,
                new ToolContext(temporaryDirectory, Map.of()));
        assertEquals(Applicability.Status.UNAVAILABLE, missing.status());
        assertEquals("CODEQL_CLI_UNAVAILABLE", missing.reasonCode());

        Applicability mismatch = adapter.checkApplicability(project, tools(executable, "2.26.1"));
        assertEquals(Applicability.Status.UNAVAILABLE, mismatch.status());
        assertEquals("CODEQL_CLI_VERSION_MISMATCH", mismatch.reasonCode());
    }

    @Test
    void goldenFindingPreservesRealSourcePropagationAndSink() throws Exception {
        Path projectRoot = copyProject(temporaryDirectory.resolve("finding-project"));
        ProjectContext project = project(projectRoot);
        Path output = Files.createDirectories(temporaryDirectory.resolve("finding-output"));
        Path report = copyReport("findings.sarif", output.resolve("report.sarif"));
        CodeqlAdapter adapter = new CodeqlAdapter(createPinnedQuerySuite());

        NormalizationResult normalized = adapter.normalize(scan(project, output), artifacts(report, output,
                ExecutionResult.Status.SUCCEEDED, 0));
        JsonNode expected = new ObjectMapper().readTree(resource("expected-findings.json").toFile());

        assertEquals(expected.path("count").asInt(), normalized.findings().size());
        var finding = normalized.findings().get(0);
        assertEquals(expected.path("category").asText(), finding.category().name());
        assertEquals(expected.path("severity").asText(), finding.severity().name());
        assertEquals(expected.path("confidence").asText(), finding.confidence().name());
        assertEquals(expected.path("ruleFamily").asText(), finding.ruleFamily());
        assertEquals(expected.path("path").asText(), finding.location().path());
        assertEquals(expected.path("line").asInt(), finding.location().startLine());
        assertTrue(finding.snippet().text().contains("Runtime.getRuntime().exec"));
        assertTrue(finding.identifiers().cwe().contains(expected.path("cwe").asText()));
        assertEquals(1, finding.dataFlows().size());
        List<String> kinds = finding.dataFlows().get(0).nodes().stream()
                .map(node -> node.kind().name()).toList();
        assertEquals(new ObjectMapper().convertValue(expected.path("flowKinds"), List.class), kinds);
        assertEquals(List.of(8, 9, 10), finding.dataFlows().get(0).nodes().stream()
                .map(node -> node.location().startLine()).toList());
        assertEquals(EngineStatus.SUCCEEDED, normalized.coverage().status());
        assertEquals(1, normalized.coverage().rawHitCount());
        assertEquals(CodeqlAdapter.REPORT_ARTIFACT, finding.evidence().get(0).rawArtifact());
    }

    @Test
    void cleanPartialMalformedAndFailedExecutionHaveDistinctOutcomes() throws Exception {
        Path projectRoot = copyProject(temporaryDirectory.resolve("outcome-project"));
        ProjectContext project = project(projectRoot);
        CodeqlAdapter adapter = new CodeqlAdapter(createPinnedQuerySuite());

        Path cleanOutput = Files.createDirectory(temporaryDirectory.resolve("clean-output"));
        Path clean = copyReport("clean.sarif", cleanOutput.resolve("report.sarif"));
        NormalizationResult cleanResult = adapter.normalize(scan(project, cleanOutput), artifacts(clean, cleanOutput,
                ExecutionResult.Status.SUCCEEDED, 0));
        assertTrue(cleanResult.findings().isEmpty());
        assertEquals(EngineStatus.SUCCEEDED, cleanResult.coverage().status());

        Path partialOutput = Files.createDirectory(temporaryDirectory.resolve("partial-output"));
        Path partial = copyReport("partial.sarif", partialOutput.resolve("report.sarif"));
        NormalizationResult partialResult = adapter.normalize(scan(project, partialOutput), artifacts(partial,
                partialOutput, ExecutionResult.Status.SUCCEEDED, 0));
        assertEquals(1, partialResult.findings().size());
        assertEquals(EngineStatus.PARTIAL, partialResult.coverage().status());
        assertFalse(partialResult.warnings().isEmpty());

        Path malformedOutput = Files.createDirectory(temporaryDirectory.resolve("malformed-output"));
        Path malformed = copyReport("malformed.sarif", malformedOutput.resolve("report.sarif"));
        ArtifactValidation invalid = adapter.validate(artifacts(malformed, malformedOutput,
                ExecutionResult.Status.SUCCEEDED, 0));
        assertFalse(invalid.valid());
        assertTrue(invalid.errors().contains("REPORT_JSON_INVALID"));
        assertThrows(IOException.class, () -> adapter.normalize(scan(project, malformedOutput),
                artifacts(malformed, malformedOutput, ExecutionResult.Status.SUCCEEDED, 0)));

        Path failureOutput = Files.createDirectory(temporaryDirectory.resolve("failure-output"));
        Path failure = copyReport("failure.sarif", failureOutput.resolve("report.sarif"));
        ArtifactValidation failed = adapter.validate(artifacts(failure, failureOutput,
                ExecutionResult.Status.FAILED, 2));
        assertTrue(failed.errors().contains("EXECUTION_FAILED"));
    }

    @Test
    void invalidFlowLocationCreatesWarningWithoutFabricatingNodes() throws Exception {
        Path projectRoot = copyProject(temporaryDirectory.resolve("invalid-flow-project"));
        ProjectContext project = project(projectRoot);
        Path output = Files.createDirectories(temporaryDirectory.resolve("invalid-flow-output"));
        ObjectMapper mapper = new ObjectMapper();
        JsonNode sarif = mapper.readTree(resource("findings.sarif").toFile());
        ObjectNode artifactLocation = (ObjectNode) sarif.path("runs").path(0).path("results").path(0)
                .path("codeFlows").path(0).path("threadFlows").path(0).path("locations").path(1)
                .path("location").path("physicalLocation").path("artifactLocation");
        artifactLocation.put("uri", "../escaped.java");
        Path report = output.resolve("report.sarif");
        mapper.writeValue(report.toFile(), sarif);
        CodeqlAdapter adapter = new CodeqlAdapter(createPinnedQuerySuite());

        NormalizationResult normalized = adapter.normalize(scan(project, output), artifacts(report, output,
                ExecutionResult.Status.SUCCEEDED, 0));

        assertEquals(1, normalized.findings().size());
        assertTrue(normalized.findings().get(0).dataFlows().isEmpty());
        assertEquals(EngineStatus.PARTIAL, normalized.coverage().status());
        assertTrue(normalized.warnings().stream().anyMatch(warning -> warning.contains("flow omitted")));
    }

    @Test
    void missingSarifKindsNeverFabricatesSourceOrSink() throws Exception {
        Path projectRoot = copyProject(temporaryDirectory.resolve("unlabelled-flow-project"));
        ProjectContext project = project(projectRoot);
        Path output = Files.createDirectories(temporaryDirectory.resolve("unlabelled-flow-output"));
        ObjectMapper mapper = new ObjectMapper();
        JsonNode sarif = mapper.readTree(resource("findings.sarif").toFile());
        for (JsonNode location : sarif.path("runs").path(0).path("results").path(0)
                .path("codeFlows").path(0).path("threadFlows").path(0).path("locations")) {
            ((ObjectNode) location).remove("kinds");
        }
        Path report = output.resolve("report.sarif");
        mapper.writeValue(report.toFile(), sarif);

        NormalizationResult normalized = new CodeqlAdapter(createPinnedQuerySuite()).normalize(
                scan(project, output), artifacts(report, output, ExecutionResult.Status.SUCCEEDED, 0));

        assertEquals(1, normalized.findings().size());
        assertTrue(normalized.findings().get(0).dataFlows().isEmpty());
        assertEquals(EngineStatus.PARTIAL, normalized.coverage().status());
        assertTrue(normalized.warnings().stream().anyMatch(warning -> warning.contains("explicit SARIF source")));
    }

    @Test
    void codeqlDataflowRoleTaxaAreAcceptedAsExplicitSourceAndSinkEvidence() throws Exception {
        Path projectRoot = copyProject(temporaryDirectory.resolve("taxa-flow-project"));
        ProjectContext project = project(projectRoot);
        Path output = Files.createDirectories(temporaryDirectory.resolve("taxa-flow-output"));
        ObjectMapper mapper = new ObjectMapper();
        JsonNode sarif = mapper.readTree(resource("findings.sarif").toFile());
        JsonNode locations = sarif.path("runs").path(0).path("results").path(0)
                .path("codeFlows").path(0).path("threadFlows").path(0).path("locations");
        for (JsonNode location : locations) {
            ((ObjectNode) location).remove("kinds");
        }
        addCodeqlDataflowRole((ObjectNode) locations.path(0), "source");
        addCodeqlDataflowRole((ObjectNode) locations.path(locations.size() - 1), "sink");
        Path report = output.resolve("report.sarif");
        mapper.writeValue(report.toFile(), sarif);

        NormalizationResult normalized = new CodeqlAdapter(createPinnedQuerySuite()).normalize(
                scan(project, output), artifacts(report, output, ExecutionResult.Status.SUCCEEDED, 0));

        assertEquals(1, normalized.findings().size());
        assertEquals(1, normalized.findings().get(0).dataFlows().size());
        assertEquals(DataFlowNode.Kind.SOURCE,
                normalized.findings().get(0).dataFlows().get(0).nodes().get(0).kind());
        assertEquals(DataFlowNode.Kind.SINK, normalized.findings().get(0).dataFlows().get(0).nodes()
                .get(normalized.findings().get(0).dataFlows().get(0).nodes().size() - 1).kind());
        assertEquals(EngineStatus.SUCCEEDED, normalized.coverage().status());
        assertTrue(normalized.warnings().isEmpty());
    }

    private void addCodeqlDataflowRole(ObjectNode location, String role) {
        ObjectNode properties = location.putArray("taxa").addObject().putObject("properties");
        properties.put("CodeQL/DataflowRole", role);
    }

    @Test
    void workflowDeletesOnlyValidatedDatabaseAndReturnsOnlySarifArtifact() throws Exception {
        Path suite = createPinnedQuerySuite();
        Path projectRoot = copyProject(temporaryDirectory.resolve("workflow-project"));
        ProjectContext project = project(projectRoot);
        Path output = temporaryDirectory.resolve("workflow-output");
        ScanContext scan = scan(project, output);
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");
        CodeqlAdapter adapter = new CodeqlAdapter(suite);
        List<ExecutionSpec> calls = new ArrayList<>();
        ExecutionBackend fake = (specification, cancellation) -> {
            calls.add(specification);
            if (calls.size() == 1) {
                Path database = Files.createDirectories(adapter.databaseDirectory(scan));
                Files.writeString(database.resolve("sentinel"), "database");
                Files.writeString(Files.createDirectories(database.resolve("db-java/default/cache"))
                        .resolve("cache-entry"), "cache");
            } else if (calls.size() == 4) {
                copyReport("findings.sarif", adapter.reportPath(scan));
            }
            return execution(specification.workingDirectory(), ExecutionResult.Status.SUCCEEDED, 0);
        };

        CodeqlWorkflow.Result result = new CodeqlWorkflow(fake).execute(adapter, scan,
                tools(executable, CodeqlAdapter.CLI_VERSION), CancellationToken.NONE);

        assertEquals(4, calls.size());
        assertTrue(result.databaseDeleted());
        assertFalse(Files.exists(adapter.databaseDirectory(scan)));
        assertEquals(Set.of("report"), result.artifacts().artifacts().keySet());
        assertEquals(adapter.reportPath(scan), result.artifacts().artifacts().get("report"));
    }

    @Test
    void workflowPreservesDatabaseOnAnalysisAndOutputFailure() throws Exception {
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");
        ToolContext tools = tools(executable, CodeqlAdapter.CLI_VERSION);

        Path failedRoot = copyProject(temporaryDirectory.resolve("failed-analysis-project"));
        ScanContext failedScan = scan(project(failedRoot), temporaryDirectory.resolve("failed-analysis-output"));
        CodeqlAdapter failedAdapter = new CodeqlAdapter(createPinnedQuerySuite());
        int[] failedCalls = {0};
        ExecutionBackend failedBackend = (specification, cancellation) -> {
            failedCalls[0]++;
            if (failedCalls[0] == 1) {
                Files.createDirectories(failedAdapter.databaseDirectory(failedScan));
                return execution(specification.workingDirectory(), ExecutionResult.Status.SUCCEEDED, 0);
            }
            return execution(specification.workingDirectory(),
                    failedCalls[0] == 4 ? ExecutionResult.Status.FAILED : ExecutionResult.Status.SUCCEEDED,
                    failedCalls[0] == 4 ? 2 : 0);
        };

        CodeqlWorkflow.CodeqlWorkflowException analysisFailure = assertThrows(
                CodeqlWorkflow.CodeqlWorkflowException.class,
                () -> new CodeqlWorkflow(failedBackend).execute(
                        failedAdapter, failedScan, tools, CancellationToken.NONE));
        assertEquals(CodeqlWorkflow.Phase.DATABASE_ANALYZE, analysisFailure.phase());
        assertTrue(Files.isDirectory(failedAdapter.databaseDirectory(failedScan)));

        Path invalidRoot = copyProject(temporaryDirectory.resolve("invalid-output-project"));
        ScanContext invalidScan = scan(project(invalidRoot), temporaryDirectory.resolve("invalid-output"));
        CodeqlAdapter invalidAdapter = new CodeqlAdapter(createPinnedQuerySuite());
        int[] invalidCalls = {0};
        ExecutionBackend invalidBackend = (specification, cancellation) -> {
            invalidCalls[0]++;
            if (invalidCalls[0] == 1) {
                Files.createDirectories(invalidAdapter.databaseDirectory(invalidScan));
            } else if (invalidCalls[0] == 4) {
                copyReport("malformed.sarif", invalidAdapter.reportPath(invalidScan));
            }
            return execution(specification.workingDirectory(), ExecutionResult.Status.SUCCEEDED, 0);
        };

        CodeqlWorkflow.CodeqlWorkflowException invalidOutput = assertThrows(
                CodeqlWorkflow.CodeqlWorkflowException.class,
                () -> new CodeqlWorkflow(invalidBackend).execute(
                        invalidAdapter, invalidScan, tools, CancellationToken.NONE));
        assertEquals(CodeqlWorkflow.Phase.OUTPUT_VALIDATION, invalidOutput.phase());
        assertTrue(Files.isDirectory(invalidAdapter.databaseDirectory(invalidScan)));
    }

    @Test
    void timeoutAndCancellationRemainDistinctWorkflowFailures() throws Exception {
        Path executable = Path.of(System.getProperty("java.home"), "bin", "java");
        for (ExecutionResult.Status status : List.of(
                ExecutionResult.Status.TIMED_OUT, ExecutionResult.Status.CANCELLED)) {
            Path projectRoot = copyProject(temporaryDirectory.resolve(status.name().toLowerCase() + "-project"));
            ScanContext scan = scan(project(projectRoot),
                    temporaryDirectory.resolve(status.name().toLowerCase() + "-output"));
            CodeqlAdapter adapter = new CodeqlAdapter(createPinnedQuerySuite());
            ExecutionBackend backend = (specification, cancellation) ->
                    execution(specification.workingDirectory(), status, null);

            CodeqlWorkflow.CodeqlWorkflowException failure = assertThrows(
                    CodeqlWorkflow.CodeqlWorkflowException.class,
                    () -> new CodeqlWorkflow(backend).execute(
                            adapter, scan, tools(executable, CodeqlAdapter.CLI_VERSION), CancellationToken.NONE));

            assertEquals(CodeqlWorkflow.Phase.DATABASE_INITIALIZE, failure.phase());
            assertEquals(status, failure.execution().status());
        }
    }

    @Test
    void realCodeqlDeepSmokeWhenInstallationIsProvided() throws Exception {
        String executableProperty = System.getProperty("audit.codeql.executable", "");
        String suiteProperty = System.getProperty("audit.codeql.querySuite", "");
        Assumptions.assumeTrue(!executableProperty.isBlank() && !suiteProperty.isBlank(),
                "real CodeQL installation is only required in the Deep smoke profile");
        Path executable = Path.of(executableProperty).toAbsolutePath().normalize();
        Path suite = Path.of(suiteProperty).toAbsolutePath().normalize();
        Assumptions.assumeTrue(Files.isExecutable(executable) && Files.isRegularFile(suite));
        Path projectRoot = copyProject(temporaryDirectory.resolve("real-project"));
        ProjectContext project = project(projectRoot);
        Path output = temporaryDirectory.resolve("real-output");
        ScanContext scan = scan(project, output);
        CodeqlAdapter adapter = new CodeqlAdapter(suite);

        CodeqlWorkflow.Result execution = new CodeqlWorkflow(new LocalProcessExecutionBackend()).execute(
                adapter, scan, tools(executable, CodeqlAdapter.CLI_VERSION), CancellationToken.NONE);
        NormalizationResult result = adapter.normalize(scan, execution.artifacts());

        assertTrue(result.findings().stream()
                .anyMatch(finding -> "COMMAND_INJECTION".equals(finding.ruleFamily())));
        assertTrue(result.findings().stream().filter(finding -> "COMMAND_INJECTION".equals(finding.ruleFamily()))
                .flatMap(finding -> finding.dataFlows().stream())
                .anyMatch(flow -> flow.nodes().stream().anyMatch(node -> node.kind() == DataFlowNode.Kind.SOURCE)
                        && flow.nodes().stream().anyMatch(node -> node.kind() == DataFlowNode.Kind.SINK)));
        assertFalse(Files.exists(adapter.databaseDirectory(scan)));
        assertEquals(Set.of("report"), execution.artifacts().artifacts().keySet());
    }

    private Path createPinnedQuerySuite() throws Exception {
        Path pack = Files.createDirectories(temporaryDirectory.resolve("query-pack-" + UUID.randomUUID()));
        Files.writeString(pack.resolve("qlpack.yml"), "name: codeql/java-queries\nversion: 1.11.7\n");
        Path suites = Files.createDirectories(pack.resolve("codeql-suites"));
        return Files.writeString(suites.resolve(CodeqlAdapter.QUERY_SUITE_NAME), "- queries: .\n");
    }

    private ProjectContext project(Path root) {
        SourceDescriptor source = new SourceDescriptor(SourceType.ZIP, "fixture", "fixture.zip", "", "sha256");
        ProjectManifest manifest = new ProjectManifest(1, ".", "pom.xml", 17, "jar",
                List.of(new MavenModule(".", "codeql-taint-fixture", "jar")), source,
                Set.of(ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP), List.of());
        return new ProjectContext(root, manifest);
    }

    private ScanContext scan(ProjectContext project, Path output) {
        return new ScanContext(UUID.randomUUID(), ScanProfile.DEEP, project, output, null, null);
    }

    private ToolContext tools(Path executable, String version) {
        return new ToolContext(executable.getParent(), Map.of(CodeqlAdapter.ID,
                new ToolContext.ToolInstallation(executable, version, true)));
    }

    private RawArtifactSet artifacts(Path report, Path output, ExecutionResult.Status status, Integer exitCode)
            throws IOException {
        return new RawArtifactSet(CodeqlAdapter.ID, Map.of("report", report), execution(output, status, exitCode));
    }

    private ExecutionResult execution(Path output, ExecutionResult.Status status, Integer exitCode) throws IOException {
        Files.createDirectories(output);
        Path stdout = output.resolve("stdout.log");
        Path stderr = output.resolve("stderr.log");
        Files.writeString(stdout, "");
        Files.writeString(stderr, "");
        Instant started = Instant.parse("2026-08-12T00:00:00Z");
        return new ExecutionResult(status, exitCode, started, started.plusSeconds(1), Duration.ofSeconds(1),
                ProcessHandle.current().pid(), stdout, stderr, false, false, "");
    }

    private Path copyProject(Path destination) throws Exception {
        Path resource = resource("project");
        try (var paths = Files.walk(resource)) {
            for (Path source : paths.toList()) {
                Path target = destination.resolve(resource.relativize(source).toString());
                if (Files.isDirectory(source)) Files.createDirectories(target);
                else Files.copy(source, target);
            }
        }
        return destination.toAbsolutePath().normalize();
    }

    private Path copyReport(String name, Path destination) throws IOException {
        Files.createDirectories(destination.getParent());
        try (InputStream input = getClass().getResourceAsStream(FIXTURE + name)) {
            if (input == null) throw new IOException("missing fixture " + name);
            Files.write(destination, input.readAllBytes());
        }
        return destination;
    }

    private Path resource(String name) throws Exception {
        return Path.of(getClass().getResource(FIXTURE + name).toURI());
    }
}
