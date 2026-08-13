package io.github.uprxiao.audit.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.finding.ComponentEvidence;
import io.github.uprxiao.audit.finding.Confidence;
import io.github.uprxiao.audit.finding.ConservativeFindingDeduplicator;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingApplicability;
import io.github.uprxiao.audit.finding.FindingDisposition;
import io.github.uprxiao.audit.finding.FindingEvidence;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ReviewState;
import io.github.uprxiao.audit.finding.ScanProfile;
import io.github.uprxiao.audit.finding.Severity;
import io.github.uprxiao.audit.finding.SourceLocation;
import io.github.uprxiao.audit.finding.SourceType;
import io.github.uprxiao.audit.finding.VulnerabilityIdentifiers;
import io.github.uprxiao.audit.intake.MavenModule;
import io.github.uprxiao.audit.intake.ProjectContext;
import io.github.uprxiao.audit.intake.ProjectManifest;
import io.github.uprxiao.audit.intake.SourceDescriptor;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FindingGovernanceBenchmarkTest {

    private static final Instant REVIEW_TIME = Instant.parse("2026-08-13T12:00:00Z");
    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    @TempDir
    Path temporaryDirectory;

    @Test
    void classifiesAllFortyEightReviewedResultsWithoutDeletingDetectorEvidence() throws Exception {
        JsonNode truth = truth();
        ProjectContext project = project("class App {}\n");
        List<Finding> sourceCandidates = new ArrayList<>();
        List<Finding> dependencyCandidates = new ArrayList<>();
        truth.path("falsePositiveFingerprints").forEach(value -> sourceCandidates.add(sourceFinding(value.asText())));
        truth.path("conditionalDefectFingerprints").forEach(value -> sourceCandidates.add(sourceFinding(value.asText())));
        truth.path("dependencies").forEach(value -> dependencyCandidates.add(dependencyFinding(
                value.path("id").asText(), value.path("purl").asText())));

        assertEquals(48, sourceCandidates.size() + dependencyCandidates.size(),
                "the committed benchmark must represent the complete reviewed queue");
        List<Finding> deduplicated = new ArrayList<>(sourceCandidates);
        deduplicated.addAll(new ConservativeFindingDeduplicator().deduplicate(dependencyCandidates).findings());
        assertEquals(47, deduplicated.size(), "the same CVE/component with a default type=jar qualifier must merge");

        FindingGovernanceResult result = service(REVIEW_TIME).assess(project, deduplicated);
        assertTrue(result.warnings().isEmpty());
        assertEquals(25, count(result, FindingApplicability.FALSE_POSITIVE));
        assertEquals(8, count(result, FindingApplicability.CONFIRMED_DEFECT));
        assertEquals(7, count(result, FindingApplicability.NOT_AFFECTED));
        assertEquals(7, count(result, FindingApplicability.TRIGGER_NOT_FOUND));
        assertEquals(0, result.findings().stream()
                .filter(finding -> finding.governance().disposition() == FindingDisposition.ACTIONABLE).count());
        assertEquals(15, result.findings().stream()
                .filter(finding -> finding.governance().disposition() == FindingDisposition.CONDITIONAL).count());
        assertEquals(48, result.findings().stream().mapToInt(finding -> finding.evidence().size()).sum(),
                "deduplication and governance must retain both scanner evidence records");
    }

    @Test
    void positiveTriggerPromotesVersionMatchToActionableAndUnknownFingerprintIsNotHidden() throws Exception {
        ProjectContext project = project("class EmbeddedConfig { RewriteValve valve; }\n");
        Finding dependency = dependencyFinding("CVE-2026-59083",
                "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@11.0.22");
        Finding unknownNullFinding = sourceFinding(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        FindingGovernanceResult result = service(REVIEW_TIME).assess(project, List.of(dependency, unknownNullFinding));

        Finding promoted = result.findings().get(0);
        assertEquals(FindingApplicability.TRIGGER_PRESENT, promoted.governance().applicability());
        assertEquals(FindingDisposition.ACTIONABLE, promoted.governance().disposition());
        assertFalse(promoted.governance().evidence().isEmpty());
        Finding unknown = result.findings().get(1);
        assertEquals(FindingDisposition.ACTIONABLE, unknown.governance().disposition());
        assertEquals(FindingApplicability.UNKNOWN, unknown.governance().applicability());
    }

    @Test
    void expiredReviewStopsSuppressingSourceResultAndEmitsAuditWarning() throws Exception {
        String reviewed = truth().path("falsePositiveFingerprints").get(0).asText();
        FindingGovernanceResult result = service(Instant.parse("2026-11-14T00:00:00Z"))
                .assess(project("class App {}\n"), List.of(sourceFinding(reviewed)));

        assertEquals(FindingDisposition.ACTIONABLE, result.findings().get(0).governance().disposition());
        assertEquals(FindingApplicability.UNKNOWN, result.findings().get(0).governance().applicability());
        assertTrue(result.warnings().stream().anyMatch(value -> value.startsWith("GOVERNANCE_EXPIRED:")));
    }

    @Test
    void rejectsIncompleteGovernancePolicyBeforeAnyScanStarts() throws Exception {
        Path malformed = temporaryDirectory.resolve("malformed-governance.json");
        Files.writeString(malformed, """
                {
                  "schemaVersion": 1,
                  "projects": [{
                    "id": "missing-expiry-and-assessment",
                    "projectArtifactId": "java-code-audit-platform",
                    "reviewedFindings": [{
                      "id": "incomplete-review",
                      "fingerprints": ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                      "rationale": "incomplete",
                      "evidence": ["manual review"]
                    }]
                  }]
                }
                """);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> new FindingGovernanceService(malformed, json, Clock.fixed(REVIEW_TIME, ZoneOffset.UTC)));

        assertTrue(failure.getMessage().contains("disposition and applicability"));
    }

    @Test
    void projectPolicyDoesNotLeakThroughAnIdenticallyNamedChildModule() throws Exception {
        String reviewed = truth().path("falsePositiveFingerprints").get(0).asText();
        ProjectContext unrelated = project("class App {}\n", List.of(
                new MavenModule(".", "unrelated-root", "pom"),
                new MavenModule("child", "java-code-audit-platform", "jar")));

        Finding result = service(REVIEW_TIME).assess(unrelated, List.of(sourceFinding(reviewed))).findings().get(0);

        assertEquals(FindingDisposition.ACTIONABLE, result.governance().disposition());
        assertEquals(FindingApplicability.UNKNOWN, result.governance().applicability());
    }

    private long count(FindingGovernanceResult result, FindingApplicability applicability) {
        return result.findings().stream()
                .filter(finding -> finding.governance().applicability() == applicability).count();
    }

    private FindingGovernanceService service(Instant instant) throws Exception {
        Path root = Path.of(System.getProperty("maven.multiModuleProjectDirectory", "../.."))
                .toAbsolutePath().normalize();
        return new FindingGovernanceService(root.resolve("config/rules/finding-governance.json"), json,
                Clock.fixed(instant, ZoneOffset.UTC));
    }

    private ProjectContext project(String source) throws Exception {
        return project(source, List.of(new MavenModule(".", "java-code-audit-platform", "pom")));
    }

    private ProjectContext project(String source, List<MavenModule> modules) throws Exception {
        Files.createDirectories(temporaryDirectory.resolve("src/main/java"));
        Files.writeString(temporaryDirectory.resolve("src/main/java/App.java"), source);
        Files.writeString(temporaryDirectory.resolve("pom.xml"), "<project/>\n");
        Path jar = temporaryDirectory.resolve("backend/audit-api/target/app.jar");
        Files.createDirectories(jar.getParent());
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("BOOT-INF/classes/App.class"));
            output.write(new byte[] {0});
            output.closeEntry();
        }
        ProjectManifest manifest = new ProjectManifest(1, ".", "pom.xml", 17, "pom",
                modules,
                new SourceDescriptor(SourceType.ZIP, "fixture", "", "", "sha256"),
                Set.of(ScanProfile.DEEP), List.of());
        return new ProjectContext(temporaryDirectory, manifest);
    }

    private Finding sourceFinding(String fingerprint) {
        String id = "F-" + fingerprint.substring("sha256:".length(), "sha256:".length() + 20);
        FindingEvidence evidence = new FindingEvidence("spotbugs", "4.9.3",
                "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", "2", "raw/spotbugs/report.xml", id,
                Map.of("method", "fixture"));
        return new Finding(id, fingerprint, 1, IssueCategory.CORRECTNESS, Severity.P2, Confidence.MEDIUM,
                "NULL_DEREFERENCE", "可能的空指针", "Possible null pointer", "", "possible null", "", "review",
                "java-code-audit-platform", new SourceLocation(
                        "src/main/java/Reviewed" + fingerprint.substring(7, 19) + ".java", 1, 0, 1, 1), null,
                VulnerabilityIdentifiers.EMPTY, null, List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    private Finding dependencyFinding(String vulnerabilityId, String purl) {
        boolean ghsa = vulnerabilityId.startsWith("GHSA-");
        VulnerabilityIdentifiers identifiers = new VulnerabilityIdentifiers(List.of(),
                ghsa ? List.of() : List.of(vulnerabilityId), ghsa ? List.of(vulnerabilityId) : List.of(), List.of());
        String fingerprint = "sha256:" + java.util.HexFormat.of().formatHex(hash(vulnerabilityId + purl));
        String artifact = purl.substring(purl.lastIndexOf('/') + 1, purl.indexOf('@'));
        String version = purl.substring(purl.indexOf('@') + 1).split("\\?", 2)[0];
        ComponentEvidence component = new ComponentEvidence(purl, "fixture", artifact, version, "compile", false,
                List.of("java-code-audit-platform"), List.of());
        FindingEvidence evidence = new FindingEvidence(purl.contains("?type=jar") ? "trivy-artifact" : "dependency-check",
                "1", vulnerabilityId, "HIGH", "raw/dependency/report.json", vulnerabilityId, Map.of());
        return new Finding("F-" + fingerprint.substring(7, 27), fingerprint, 1,
                IssueCategory.DEPENDENCY_VULNERABILITY, Severity.P1, Confidence.HIGH,
                "DEPENDENCY_VULNERABILITY", vulnerabilityId, vulnerabilityId, "", vulnerabilityId, "", "upgrade",
                "java-code-audit-platform", null, null, identifiers, component, List.of(), List.of(evidence), null,
                ReviewState.UNREVIEWED);
    }

    private byte[] hash(String value) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private JsonNode truth() throws Exception {
        try (InputStream input = getClass().getResourceAsStream(
                "/rule-governance/2026-08-13-actionable-truth.json")) {
            return json.readTree(input);
        }
    }
}
