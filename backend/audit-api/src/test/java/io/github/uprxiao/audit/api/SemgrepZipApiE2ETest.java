package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@EnabledIfSystemProperty(named = "audit.quick.root", matches = ".+")
class SemgrepZipApiE2ETest {

    private static final Path DATA_ROOT = createDataRoot();
    private static final Path REPOSITORY_ROOT = Path.of("../..").toAbsolutePath().normalize();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("audit.data-root", () -> DATA_ROOT.toString());
        registry.add("audit.tools.semgrep-executable", () -> System.getProperty("audit.semgrep.executable"));
        registry.add("audit.tools.quick-root", () -> System.getProperty("audit.quick.root"));
        registry.add("audit.rules.semgrep", () -> System.getProperty("audit.semgrep.rules"));
        registry.add("audit.rules.gitleaks", () -> REPOSITORY_ROOT.resolve("config/rules/gitleaks/gitleaks.toml").toString());
        registry.add("audit.rules.pmd", () -> REPOSITORY_ROOT.resolve("config/rules/pmd/java-audit.xml").toString());
        registry.add("audit.rules.checkstyle", () -> REPOSITORY_ROOT.resolve("config/rules/checkstyle/java-audit.xml").toString());
        registry.add("audit.rules.spotbugs-exclude", () -> REPOSITORY_ROOT.resolve("config/rules/spotbugs-exclude.xml").toString());
        registry.add("audit.concurrency.max-concurrent-scan-jobs", () -> "1");
        registry.add("audit.concurrency.max-queued-scan-jobs", () -> "2");
    }

    @Autowired
    MockMvc mvc;

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void uploadPollFindingsDownloadAndCleanupCompleteEndToEnd() throws Exception {
        MockMultipartFile source = new MockMultipartFile(
                "source", "vulnerable.zip", "application/zip", vulnerableProjectZip());
        MockMultipartFile request = new MockMultipartFile(
                "request", "", MediaType.APPLICATION_JSON_VALUE,
                "{\"displayName\":\"vulnerable-fixture\",\"profile\":\"QUICK\"}".getBytes(StandardCharsets.UTF_8));

        MvcResult accepted = mvc.perform(multipart("/api/v1/scans/zip").file(source).file(request))
                .andExpect(status().isAccepted())
                .andExpect(header().exists("Location"))
                .andReturn();
        String location = accepted.getResponse().getHeader("Location");
        JsonNode created = json.readTree(accepted.getResponse().getContentAsByteArray());
        String scanId = created.path("scanId").asText();
        assertNotNull(location);
        assertEquals("QUEUED", created.path("status").asText());
        assertEquals(6, created.path("plannedEngines").size());

        JsonNode terminal = waitForTerminal(location);
        assertEquals("COMPLETED", terminal.path("status").asText(), terminal.toPrettyString());
        assertTrue(terminal.path("summary").path("uniqueFindingCount").asInt() >= 2);
        assertEquals(6, terminal.path("progress").path("enginesTotal").asInt());
        assertFalse(terminal.path("summary").path("partial").asBoolean());

        MvcResult findings = mvc.perform(get("/api/v1/scans/{scanId}/findings", scanId))
                .andExpect(status().isOk()).andReturn();
        JsonNode findingArray = json.readTree(findings.getResponse().getContentAsByteArray());
        assertTrue(findingArray.size() >= 2);
        assertTrue(java.util.stream.StreamSupport.stream(findingArray.spliterator(), false)
                .anyMatch(finding -> finding.path("ruleFamily").asText().equals("SQL_INJECTION")));
        mvc.perform(get("/api/v1/scans/{scanId}/findings/{findingId}",
                        scanId, findingArray.get(0).path("id").asText()))
                .andExpect(status().isOk());

        MvcResult engines = mvc.perform(get("/api/v1/scans/{scanId}/engines", scanId))
                .andExpect(status().isOk()).andReturn();
        assertEquals(6, json.readTree(engines.getResponse().getContentAsByteArray()).size());
        mvc.perform(get("/api/v1/scans/{scanId}/engines/semgrep", scanId))
                .andExpect(status().isOk());

        MvcResult report = mvc.perform(get("/api/v1/scans/{scanId}/reports/json", scanId))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", MediaType.APPLICATION_JSON_VALUE))
                .andReturn();
        JsonNode reportJson = json.readTree(report.getResponse().getContentAsByteArray());
        assertTrue(reportJson.path("summary").path("uniqueFindingCount").asInt() >= 2);
        assertEquals(6, reportJson.path("engines").size());

        MvcResult archive = mvc.perform(get("/api/v1/scans/{scanId}/reports/archive", scanId))
                .andExpect(status().isOk()).andReturn();
        Set<String> archiveEntries = entries(archive.getResponse().getContentAsByteArray());
        assertTrue(archiveEntries.contains("report.html"));
        assertTrue(archiveEntries.contains("report.json"));
        assertTrue(archiveEntries.contains("raw/semgrep/report.json"));
        assertTrue(archiveEntries.contains("raw/gitleaks/report.json"));
        assertTrue(archiveEntries.contains("raw/pmd/report.json"));
        assertTrue(archiveEntries.contains("raw/pmd-cpd/report.xml"));
        assertTrue(archiveEntries.contains("raw/checkstyle/report.xml"));
        assertTrue(archiveEntries.contains("raw/trivy-repository/report.json"));
        assertFalse(archiveEntries.stream().anyMatch(name -> name.contains("source") || name.contains("workspace")));

        Path jobRoot = DATA_ROOT.resolve("jobs").resolve(scanId);
        assertFalse(Files.exists(jobRoot.resolve("source")));
        assertFalse(Files.exists(jobRoot.resolve("workspace")));
        assertTrue(Files.exists(jobRoot.resolve("job.json")));
        assertTrue(Files.exists(jobRoot.resolve("report/report.html")));

        mvc.perform(delete("/api/v1/scans/{scanId}", scanId)).andExpect(status().isNoContent());
        assertFalse(Files.exists(jobRoot));
        mvc.perform(get("/api/v1/scans/{scanId}", scanId)).andExpect(status().isNotFound());
    }

    private JsonNode waitForTerminal(String location) throws Exception {
        JsonNode state = null;
        for (int attempt = 0; attempt < 200; attempt++) {
            MvcResult response = mvc.perform(get(location)).andExpect(status().isOk()).andReturn();
            state = json.readTree(response.getResponse().getContentAsByteArray());
            String status = state.path("status").asText();
            if (Set.of("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED", "INTERRUPTED").contains(status)) {
                return state;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("scan did not terminate: " + state);
    }

    private byte[] vulnerableProjectZip() throws Exception {
        String pom = """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion><groupId>example</groupId>
                  <artifactId>api-e2e</artifactId><version>1.0.0</version>
                  <properties><maven.compiler.release>17</maven.compiler.release></properties>
                </project>
                """;
        String java = """
                package example;
                import java.sql.Connection;
                final class UnsafeController {
                  void find(Connection c, String name) throws Exception {
                    c.createStatement().executeQuery("select * from users where name='" + name + "'");
                  }
                  void run(String value) throws Exception {
                    Runtime.getRuntime().exec("/usr/bin/example --value=" + value);
                  }
                }
                """;
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            add(zip, "project/pom.xml", pom);
            add(zip, "project/src/main/java/example/UnsafeController.java", java);
        }
        return bytes.toByteArray();
    }

    private void add(ZipOutputStream zip, String name, String content) throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

    private Set<String> entries(byte[] archive) throws Exception {
        Set<String> result = new HashSet<>();
        try (ZipInputStream zip = new ZipInputStream(new java.io.ByteArrayInputStream(archive))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                result.add(entry.getName());
            }
        }
        return result;
    }

    private static Path createDataRoot() {
        try {
            return Files.createTempDirectory("audit-api-e2e-");
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }
}
