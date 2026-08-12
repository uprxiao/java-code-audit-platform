package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.finding.EngineCoverage;
import io.github.uprxiao.audit.finding.EngineStatus;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.orchestrator.DefaultScanPlanner;
import io.github.uprxiao.audit.process.MavenProcessAdapter;
import io.github.uprxiao.audit.process.MavenProcessConfiguration;
import io.github.uprxiao.audit.scanner.Applicability;
import io.github.uprxiao.audit.scanner.ArtifactValidation;
import io.github.uprxiao.audit.scanner.EngineDescriptor;
import io.github.uprxiao.audit.scanner.EngineId;
import io.github.uprxiao.audit.scanner.ExecutionResult;
import io.github.uprxiao.audit.scanner.ExecutionSpec;
import io.github.uprxiao.audit.scanner.ExpectedArtifact;
import io.github.uprxiao.audit.scanner.NormalizationResult;
import io.github.uprxiao.audit.scanner.RawArtifactSet;
import io.github.uprxiao.audit.scanner.RedactionPolicy;
import io.github.uprxiao.audit.scanner.ResourceClass;
import io.github.uprxiao.audit.scanner.ResourceRequest;
import io.github.uprxiao.audit.scanner.ScanContext;
import io.github.uprxiao.audit.scanner.ScannerAdapter;
import io.github.uprxiao.audit.scanner.ToolContext;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@Import(StandardProfileApiE2ETest.FakeConfiguration.class)
class StandardProfileApiE2ETest {

    private static final Path DATA_ROOT = createDataRoot();
    private static final Path REPOSITORY_ROOT = Path.of("../..").toAbsolutePath().normalize();
    private static final Set<String> TERMINAL = Set.of(
            "COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED", "INTERRUPTED");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("audit.data-root", DATA_ROOT::toString);
        registry.add("audit.storage.minimum-free-bytes", () -> "1");
        registry.add("audit.concurrency.max-concurrent-scan-jobs", () -> "1");
        registry.add("audit.concurrency.max-queued-scan-jobs", () -> "3");
        registry.add("audit.rules.semgrep", () -> rule("config/rules/semgrep/java-audit.yaml"));
        registry.add("audit.rules.gitleaks", () -> rule("config/rules/gitleaks/gitleaks.toml"));
        registry.add("audit.rules.pmd", () -> rule("config/rules/pmd/java-audit.xml"));
        registry.add("audit.rules.checkstyle", () -> rule("config/rules/checkstyle/java-audit.xml"));
        registry.add("audit.rules.spotbugs-exclude", () -> rule("config/rules/spotbugs-exclude.xml"));
    }

    @Autowired
    MockMvc mvc;

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void healthAndSingleAndMultiModulePlansExposeExactlyFourteenStandardEngines() throws Exception {
        JsonNode health = json.readTree(mvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
        assertEquals("AVAILABLE", health.path("profiles").path("STANDARD").asText());
        assertEquals("UNAVAILABLE", health.path("profiles").path("DEEP").asText());

        for (Map<String, String> files : List.of(singleModuleFiles(false), multiModuleFiles())) {
            JsonNode created = submit(files, """
                    {"displayName":"fake-standard","profile":"STANDARD",
                     "mavenProfiles":["opensource"],"mavenProperties":{"revision":"1.0.0"}}
                    """);
            assertEquals(14, created.path("plannedEngines").size());
            assertEquals(14, unique(created.path("plannedEngines")).size());
            JsonNode terminal = waitForTerminal(created.path("scanId").asText());
            assertEquals("COMPLETED", terminal.path("status").asText(), terminal.toPrettyString());
            assertEquals(14, terminal.path("progress").path("enginesTotal").asInt());
            JsonNode engines = engines(created.path("scanId").asText());
            assertEquals(14, engines.size());
            assertTrue(java.util.stream.StreamSupport.stream(engines.spliterator(), false)
                    .allMatch(engine -> "SUCCEEDED".equals(engine.path("status").asText())));
        }
    }

    @Test
    void failedMavenBuildKeepsAllQuickEnginesAndSkipsEveryBuildDependentEngine() throws Exception {
        JsonNode created = submit(singleModuleFiles(true),
                "{\"displayName\":\"build-failure\",\"profile\":\"STANDARD\"}");
        JsonNode terminal = waitForTerminal(created.path("scanId").asText());

        assertEquals("COMPLETED_WITH_ERRORS", terminal.path("status").asText(), terminal.toPrettyString());
        JsonNode engines = engines(created.path("scanId").asText());
        Set<String> quick = Set.of(
                "gitleaks", "semgrep", "pmd", "pmd-cpd", "checkstyle", "trivy-repository");
        int succeededQuick = 0;
        int skippedStandard = 0;
        for (JsonNode engine : engines) {
            if (quick.contains(engine.path("engineId").asText())) {
                assertEquals("SUCCEEDED", engine.path("status").asText(), engine.toPrettyString());
                succeededQuick++;
            } else {
                assertEquals("SKIPPED", engine.path("status").asText(), engine.toPrettyString());
                assertEquals("SKIPPED_DEPENDENCY_FAILED", engine.path("failure").path("code").asText());
                skippedStandard++;
            }
        }
        assertEquals(6, succeededQuick);
        assertEquals(8, skippedStandard);
    }

    @Test
    void rejectsMavenCommandInjectionBeforeAJobIsCreated() throws Exception {
        MockMultipartFile source = new MockMultipartFile(
                "source", "unsafe.zip", "application/zip", zip(singleModuleFiles(false)));
        MockMultipartFile request = new MockMultipartFile(
                "request", "", MediaType.APPLICATION_JSON_VALUE,
                "{\"profile\":\"STANDARD\",\"mavenProperties\":{\"revision\":\"$(touch-pwned)\"}}"
                        .getBytes(StandardCharsets.UTF_8));
        mvc.perform(multipart("/api/v1/scans/zip").file(source).file(request))
                .andExpect(status().isBadRequest());
    }

    private JsonNode submit(Map<String, String> files, String requestJson) throws Exception {
        MockMultipartFile source = new MockMultipartFile(
                "source", "fixture.zip", "application/zip", zip(files));
        MockMultipartFile request = new MockMultipartFile(
                "request", "", MediaType.APPLICATION_JSON_VALUE,
                requestJson.getBytes(StandardCharsets.UTF_8));
        MvcResult accepted = mvc.perform(multipart("/api/v1/scans/zip").file(source).file(request))
                .andExpect(status().isAccepted()).andReturn();
        return json.readTree(accepted.getResponse().getContentAsByteArray());
    }

    private JsonNode waitForTerminal(String scanId) throws Exception {
        JsonNode state = null;
        for (int attempt = 0; attempt < 200; attempt++) {
            state = json.readTree(mvc.perform(get("/api/v1/scans/{scanId}", scanId))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
            if (TERMINAL.contains(state.path("status").asText())) {
                return state;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("scan did not terminate: " + state);
    }

    private JsonNode engines(String scanId) throws Exception {
        return json.readTree(mvc.perform(get("/api/v1/scans/{scanId}/engines", scanId))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsByteArray());
    }

    private Set<String> unique(JsonNode array) {
        Set<String> result = new HashSet<>();
        array.forEach(value -> result.add(value.asText()));
        return result;
    }

    private Map<String, String> singleModuleFiles(boolean failBuild) {
        Map<String, String> files = new LinkedHashMap<>();
        files.put("project/pom.xml", """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion><groupId>example</groupId>
                  <artifactId>single</artifactId><version>1.0.0</version>
                  <properties><maven.compiler.release>17</maven.compiler.release></properties>
                </project>
                """);
        files.put("project/src/main/java/example/App.java", failBuild
                ? "package example; final class App { BUILD_FAIL }"
                : "package example; final class App {} ");
        return files;
    }

    private Map<String, String> multiModuleFiles() {
        Map<String, String> files = new LinkedHashMap<>();
        files.put("project/pom.xml", """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion><groupId>example</groupId>
                  <artifactId>reactor</artifactId><version>1.0.0</version><packaging>pom</packaging>
                  <properties><maven.compiler.release>17</maven.compiler.release></properties>
                  <modules><module>module-a</module></modules>
                </project>
                """);
        files.put("project/module-a/pom.xml", """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion><parent><groupId>example</groupId>
                  <artifactId>reactor</artifactId><version>1.0.0</version></parent>
                  <artifactId>module-a</artifactId>
                </project>
                """);
        files.put("project/module-a/src/main/java/example/Module.java",
                "package example; final class Module {} ");
        return files;
    }

    private byte[] zip(Map<String, String> files) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(output)) {
            for (Map.Entry<String, String> file : files.entrySet()) {
                zip.putNextEntry(new ZipEntry(file.getKey()));
                zip.write(file.getValue().getBytes(StandardCharsets.UTF_8));
                zip.closeEntry();
            }
        }
        return output.toByteArray();
    }

    private static Path createDataRoot() {
        try {
            return Files.createTempDirectory("standard-api-e2e-");
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    private static String rule(String relative) {
        return REPOSITORY_ROOT.resolve(relative).toString();
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class FakeConfiguration {

        @Bean
        @Primary
        ScannerRegistry fakeScannerRegistry(AuditRuntimePaths paths, DefaultScanPlanner planner) {
            List<ScannerAdapter> adapters = new ArrayList<>();
            List<ToolInstallationHealth> health = new ArrayList<>();
            Path java = Path.of(System.getProperty("java.home"), "bin", "java");
            for (var engine : planner.plan(ScanProfile.STANDARD).engines()) {
                adapters.add(new FakeAdapter(engine.id()));
                health.add(new ToolInstallationHealth(
                        engine.id().value(), "AVAILABLE", "fake", java, "fake-sha256", "", "",
                        Instant.parse("2026-08-12T00:00:00Z")));
            }
            return new ScannerRegistry(adapters, health, paths, planner, true);
        }

        @Bean
        @Primary
        MavenProcessAdapter fakeMavenProcessAdapter(MavenProcessConfiguration configuration) {
            return new MavenProcessAdapter((specification, cancellationToken) -> {
                Path pom = Path.of(specification.command().get(specification.command().indexOf("--file") + 1));
                boolean failed;
                try (var paths = Files.walk(pom.getParent())) {
                    failed = paths.filter(Files::isRegularFile).anyMatch(file -> {
                        try {
                            return Files.readString(file).contains("BUILD_FAIL");
                        } catch (Exception exception) {
                            return false;
                        }
                    });
                }
                Path stdout = specification.workingDirectory().resolve("stdout.log");
                Path stderr = specification.workingDirectory().resolve("stderr.log");
                Files.createDirectories(specification.workingDirectory());
                Files.writeString(stdout, failed ? """
                        [INFO] Reactor Summary:
                        [INFO] single ................................ FAILURE [  0.100 s]
                        [INFO] BUILD FAILURE
                        """ : """
                        [INFO] Reactor Summary:
                        [INFO] reactor ............................... SUCCESS [  0.100 s]
                        [INFO] module-a .............................. SUCCESS [  0.100 s]
                        [INFO] BUILD SUCCESS
                        """);
                Files.writeString(stderr, failed ? "controlled build failure" : "");
                Instant now = Instant.parse("2026-08-12T00:00:00Z");
                return new ExecutionResult(
                        failed ? ExecutionResult.Status.FAILED : ExecutionResult.Status.SUCCEEDED,
                        failed ? 1 : 0, now, now.plusMillis(100), Duration.ofMillis(100), 123,
                        stdout, stderr, false, false, failed ? "process exited with code 1" : "");
            }, configuration);
        }
    }

    private static final class FakeAdapter implements ScannerAdapter {
        private final EngineDescriptor descriptor;

        private FakeAdapter(EngineId id) {
            descriptor = new EngineDescriptor(id, id.value(), false,
                    new ResourceRequest(ResourceClass.LIGHT, 1, 128), Duration.ofSeconds(30), Set.of());
        }

        @Override
        public EngineDescriptor descriptor() {
            return descriptor;
        }

        @Override
        public Applicability checkApplicability(io.github.uprxiao.audit.intake.ProjectContext project, ToolContext tools) {
            return Applicability.applicable();
        }

        @Override
        public ExecutionSpec prepare(ScanContext context, ToolContext tools) throws java.io.IOException {
            Files.createDirectories(context.engineOutputDirectory());
            String report = descriptor.id().value().equals("spotbugs") ? "report.xml" : "report.json";
            Path java = Path.of(System.getProperty("java.home"), "bin", "java");
            String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
            return new ExecutionSpec(
                    descriptor.id(),
                    List.of(java.toString(), "-cp", classpath, FakeScannerToolMain.class.getName(),
                            context.engineOutputDirectory().resolve(report).toString()),
                    context.engineOutputDirectory(),
                    Map.of(
                            "PATH", java.getParent().toString(),
                            "JAVA_HOME", System.getProperty("java.home"),
                            "HOME", context.engineOutputDirectory().toString()),
                    descriptor.defaultTimeout(), descriptor.resources(),
                    Set.of(new ExpectedArtifact(report, true, 1024)), RedactionPolicy.NONE);
        }

        @Override
        public ArtifactValidation validate(RawArtifactSet artifacts) {
            Path report = artifacts.artifacts().get("report");
            return new ArtifactValidation(report != null && Files.isRegularFile(report),
                    report != null && Files.isRegularFile(report) ? List.of() : List.of("REPORT_MISSING"));
        }

        @Override
        public NormalizationResult normalize(ScanContext context, RawArtifactSet artifacts) {
            int modules = context.project().manifest().modules().size();
            return new NormalizationResult(List.of(), new EngineCoverage(
                    descriptor.id().value(), EngineStatus.SUCCEEDED,
                    modules, modules, modules, 0, artifacts.execution().duration(), "",
                    "raw/" + descriptor.id().value() + "/report.json"), List.of());
        }
    }
}
