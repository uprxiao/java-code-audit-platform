package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.intake.SourceCredential;
import io.github.uprxiao.audit.intake.SvnCheckoutResult;
import io.github.uprxiao.audit.intake.SvnSourceCheckout;
import io.github.uprxiao.audit.finding.ScanStatus;
import io.github.uprxiao.audit.storage.JobStore;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@EnabledIfSystemProperty(named = "audit.quick.root", matches = ".+")
class SvnApiCredentialE2ETest {

    private static final String CANARY = "svn-canary-password-7ec3";
    private static final Path DATA_ROOT = createDataRoot();
    private static final Path REPOSITORY_ROOT = Path.of("../..").toAbsolutePath().normalize();
    private static final AtomicBoolean CREDENTIAL_OBSERVED = new AtomicBoolean();
    private static final CountDownLatch BLOCKING_CHECKOUT_ENTERED = new CountDownLatch(1);
    private static final CountDownLatch RELEASE_BLOCKING_CHECKOUT = new CountDownLatch(1);

    @TestBean
    SvnSourceCheckout svnSourceCheckout;

    static SvnSourceCheckout svnSourceCheckout() {
        return (url, revision, destination, credential, cancelled) -> {
            if (url.contains("/blocking")) {
                BLOCKING_CHECKOUT_ENTERED.countDown();
                try {
                    if (!RELEASE_BLOCKING_CHECKOUT.await(10, TimeUnit.SECONDS)) {
                        throw new java.io.IOException("timed out waiting to release fake SVN checkout");
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new java.io.IOException("fake SVN checkout was interrupted", exception);
                }
            }
            char[] password = credential.passwordCopy();
            try {
                if (Arrays.equals(CANARY.toCharArray(), password)) {
                    CREDENTIAL_OBSERVED.set(true);
                }
            } finally {
                Arrays.fill(password, '\0');
            }
            Files.createDirectories(destination);
            Files.writeString(destination.resolve("pom.xml"), """
                    <project xmlns="http://maven.apache.org/POM/4.0.0">
                      <modelVersion>4.0.0</modelVersion><groupId>test</groupId>
                      <artifactId>svn-fixture</artifactId><version>1</version>
                      <properties><maven.compiler.release>17</maven.compiler.release></properties>
                    </project>
                    """, StandardCharsets.UTF_8);
            long resolved = revision.number().orElse(42);
            return new SvnCheckoutResult(destination, resolved, 1, 1, Files.size(destination.resolve("pom.xml")),
                    "sha256:" + "a".repeat(64));
        };
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("audit.data-root", () -> DATA_ROOT.toString());
        registry.add("audit.storage.minimum-free-bytes", () -> "1");
        registry.add("audit.concurrency.max-concurrent-scan-jobs", () -> "1");
        registry.add("audit.concurrency.max-queued-scan-jobs", () -> "2");
        registry.add("audit.tools.semgrep-executable", () -> System.getProperty("audit.semgrep.executable"));
        registry.add("audit.tools.quick-root", () -> System.getProperty("audit.quick.root"));
        registry.add("audit.rules.semgrep", () -> System.getProperty("audit.semgrep.rules"));
        registry.add("audit.rules.gitleaks", () -> REPOSITORY_ROOT.resolve("config/rules/gitleaks/gitleaks.toml").toString());
        registry.add("audit.rules.pmd", () -> REPOSITORY_ROOT.resolve("config/rules/pmd/java-audit.xml").toString());
        registry.add("audit.rules.checkstyle", () -> REPOSITORY_ROOT.resolve("config/rules/checkstyle/java-audit.xml").toString());
        registry.add("audit.rules.spotbugs-exclude", () -> REPOSITORY_ROOT.resolve("config/rules/spotbugs-exclude.xml").toString());
    }

    @Autowired
    MockMvc mvc;

    @Autowired
    ScanService scans;

    @Autowired
    JobStore jobs;

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void acceptsCredentialedHeadWithoutPersistingThePassword() throws Exception {
        var accepted = mvc.perform(post("/api/v1/scans/svn")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"repositoryUrl":"https://svn.example.test/repo/trunk",
                                 "revision":"HEAD","username":"alice","password":"%s","profile":"QUICK"}
                                """.formatted(CANARY)))
                .andExpect(status().isAccepted())
                .andExpect(header().exists("Location"))
                .andReturn();
        String location = accepted.getResponse().getHeader("Location");
        String scanId = json.readTree(accepted.getResponse().getContentAsByteArray()).path("scanId").asText();
        JsonNode terminal = waitForTerminal(location);

        assertTrue(CREDENTIAL_OBSERVED.get());
        assertTrue(terminal.path("status").asText().startsWith("COMPLETED"), terminal.toPrettyString());
        assertTrue(terminal.path("links").has("archive"), terminal.toPrettyString());
        JsonNode persisted = json.readTree(DATA_ROOT.resolve("jobs").resolve(scanId).resolve("request.json").toFile());
        assertTrue(persisted.path("sourceCredentialsOmitted").asBoolean());
        assertFalse(persisted.has("username"));
        assertFalse(persisted.has("password"));
        String manifest = Files.readString(
                DATA_ROOT.resolve("jobs").resolve(scanId).resolve("report/manifest.json"));
        assertTrue(manifest.contains("https://svn.example.test/***"));
        assertFalse(manifest.contains("/repo/trunk"));
        assertNoCanary(DATA_ROOT);
    }

    @Test
    void acceptsAnonymousNumericRevision() throws Exception {
        var accepted = mvc.perform(post("/api/v1/scans/svn")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"repositoryUrl":"svn://svn.example.test/repo/trunk",
                                 "revision":"17","profile":"QUICK"}
                                """))
                .andExpect(status().isAccepted())
                .andReturn();
        waitForTerminal(accepted.getResponse().getHeader("Location"));
    }

    @Test
    void queuedCredentialedRequestExpiresThroughTheExistingRestartHook() throws Exception {
        var blocking = mvc.perform(post("/api/v1/scans/svn")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"repositoryUrl":"https://svn.example.test/blocking",
                                 "revision":"HEAD","profile":"QUICK"}
                                """))
                .andExpect(status().isAccepted())
                .andReturn();
        assertTrue(BLOCKING_CHECKOUT_ENTERED.await(5, TimeUnit.SECONDS));
        String queuedLocation = null;
        try {
            var queued = mvc.perform(post("/api/v1/scans/svn")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"repositoryUrl":"https://svn.example.test/repo/trunk",
                                     "username":"alice","password":"%s","profile":"QUICK"}
                                    """.formatted(CANARY)))
                    .andExpect(status().isAccepted())
                    .andReturn();
            queuedLocation = queued.getResponse().getHeader("Location");
            UUID queuedId = UUID.fromString(json.readTree(queued.getResponse().getContentAsByteArray())
                    .path("scanId").asText());

            scans.restoreQueued(jobs.find(queuedId).orElseThrow());

            var expired = jobs.find(queuedId).orElseThrow();
            assertTrue(expired.status() == ScanStatus.INTERRUPTED);
            assertTrue(expired.failure().code().equals("SOURCE_CREDENTIALS_EXPIRED"));
        } finally {
            RELEASE_BLOCKING_CHECKOUT.countDown();
        }
        waitForTerminal(blocking.getResponse().getHeader("Location"));
        waitForTerminal(queuedLocation);
        assertNoCanary(DATA_ROOT);
    }

    private JsonNode waitForTerminal(String location) throws Exception {
        JsonNode state = null;
        for (int attempt = 0; attempt < 200; attempt++) {
            var response = mvc.perform(get(location)).andExpect(status().isOk()).andReturn();
            state = json.readTree(response.getResponse().getContentAsByteArray());
            if (Set.of("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED", "INTERRUPTED")
                    .contains(state.path("status").asText())) {
                return state;
            }
            Thread.sleep(100);
        }
        throw new AssertionError("SVN scan did not terminate: " + state);
    }

    private void assertNoCanary(Path root) throws Exception {
        try (var files = Files.walk(root)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                assertFalse(new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1).contains(CANARY), file.toString());
            }
        }
    }

    private static Path createDataRoot() {
        try {
            return Files.createTempDirectory("audit-svn-api-");
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }
}
