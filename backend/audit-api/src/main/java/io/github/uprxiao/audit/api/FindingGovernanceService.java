package io.github.uprxiao.audit.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingApplicability;
import io.github.uprxiao.audit.finding.FindingDisposition;
import io.github.uprxiao.audit.finding.FindingGovernance;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.PackageUrlNormalizer;
import io.github.uprxiao.audit.finding.ReviewState;
import io.github.uprxiao.audit.finding.Severity;
import io.github.uprxiao.audit.intake.ProjectContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.zip.ZipFile;

/** Applies reviewed, expiring project evidence without mutating detector facts. */
final class FindingGovernanceService {

    private static final long MAX_TEXT_BYTES = 2L * 1024 * 1024;
    private static final Set<String> TEXT_EXTENSIONS = Set.of(
            ".java", ".xml", ".yaml", ".yml", ".properties", ".json", ".conf", ".config");

    private final GovernancePolicyDocument document;
    private final Clock clock;
    private final PackageUrlNormalizer purls = new PackageUrlNormalizer();
    private final Path policyFile;

    FindingGovernanceService(Path policyFile, ObjectMapper json, Clock clock) throws IOException {
        Objects.requireNonNull(policyFile, "policyFile");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.policyFile = policyFile.toAbsolutePath().normalize();
        if (!Files.isRegularFile(policyFile)) {
            throw new IOException("finding governance policy is unavailable: " + policyFile);
        }
        this.document = Objects.requireNonNull(json, "json").readValue(policyFile.toFile(), GovernancePolicyDocument.class);
        validate(document);
    }

    Path policyFile() {
        return policyFile;
    }

    FindingGovernanceResult assess(ProjectContext project, List<Finding> findings) throws IOException {
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(findings, "findings");
        Instant now = clock.instant();
        List<ProjectPolicy> projects = document.projects().stream().filter(policy -> applies(policy, project)).toList();
        ProjectEvidenceIndex evidenceIndex = projects.stream().anyMatch(policy -> !policy.dependencies().isEmpty())
                ? ProjectEvidenceIndex.create(project.workspaceRoot()) : ProjectEvidenceIndex.empty();
        List<String> warnings = new ArrayList<>();
        List<Finding> assessed = new ArrayList<>(findings.size());
        for (Finding finding : findings) {
            Finding reviewed = applyReviewedSets(projects, finding, now, warnings);
            if (reviewed != null) {
                assessed.add(reviewed);
                continue;
            }
            if (finding.category() == IssueCategory.DEPENDENCY_VULNERABILITY) {
                assessed.add(applyDependencyPolicies(projects, finding, evidenceIndex, now, warnings));
            } else {
                assessed.add(finding);
            }
        }
        return new FindingGovernanceResult(assessed, warnings.stream().distinct().sorted().toList());
    }

    private Finding applyReviewedSets(
            List<ProjectPolicy> projects, Finding finding, Instant now, List<String> warnings) {
        for (ProjectPolicy project : projects) {
            for (ReviewedFindingSet set : project.reviewedFindings()) {
                if (!set.fingerprints().contains(finding.fingerprint())) continue;
                if (expired(project, set.expiresAt(), now)) {
                    warnings.add("GOVERNANCE_EXPIRED:" + set.id() + ":" + finding.fingerprint());
                    return null;
                }
                FindingGovernance governance = new FindingGovernance(
                        set.disposition(), set.applicability(), set.id(), set.rationale(), set.evidence(),
                        set.upstreamSeverity(), effectiveExpiry(project, set.expiresAt()));
                ReviewState reviewState = switch (set.applicability()) {
                    case FALSE_POSITIVE -> ReviewState.FALSE_POSITIVE;
                    case CONFIRMED_DEFECT, TRIGGER_PRESENT -> ReviewState.CONFIRMED;
                    default -> finding.reviewState();
                };
                return finding.withGovernance(governance, reviewState);
            }
        }
        return null;
    }

    private Finding applyDependencyPolicies(
            List<ProjectPolicy> projects,
            Finding finding,
            ProjectEvidenceIndex evidenceIndex,
            Instant now,
            List<String> warnings) {
        for (ProjectPolicy project : projects) {
            for (DependencyPolicy policy : project.dependencies()) {
                if (!matches(policy, finding)) continue;
                if (expired(project, policy.expiresAt(), now)) {
                    warnings.add("GOVERNANCE_EXPIRED:" + policy.id() + ":" + finding.fingerprint());
                    return dependencyVersionOnly(finding, "review policy expired");
                }
                List<String> matched = evidenceIndex.matchGroups(policy.triggerPatternGroups());
                if (!matched.isEmpty()) {
                    return finding.withGovernance(new FindingGovernance(
                            FindingDisposition.ACTIONABLE, FindingApplicability.TRIGGER_PRESENT, policy.id(),
                            "Affected component version and project trigger evidence are both present",
                            matched, policy.upstreamSeverity(), effectiveExpiry(project, policy.expiresAt())),
                            ReviewState.CONFIRMED);
                }
                List<String> checked = policy.triggerPatternGroups().stream()
                        .map(group -> "not found: " + String.join(" OR ", group)).toList();
                return finding.withGovernance(new FindingGovernance(
                        policy.whenAbsentDisposition(), policy.whenAbsentApplicability(), policy.id(),
                        policy.rationale(), checked, policy.upstreamSeverity(),
                        effectiveExpiry(project, policy.expiresAt())), finding.reviewState());
            }
        }
        return dependencyVersionOnly(finding, "affected version matched; no project applicability policy matched");
    }

    private Finding dependencyVersionOnly(Finding finding, String rationale) {
        boolean knownExploited = finding.evidence().stream().anyMatch(item ->
                Boolean.TRUE.equals(item.properties().get("knownExploited")));
        FindingDisposition disposition = knownExploited
                ? FindingDisposition.ACTIONABLE : FindingDisposition.CONDITIONAL;
        return finding.withGovernance(new FindingGovernance(
                disposition, FindingApplicability.AFFECTED_VERSION, "", rationale,
                List.of("component version is within the advisory range"), "", null), finding.reviewState());
    }

    private boolean matches(DependencyPolicy policy, Finding finding) {
        if (finding.component() == null) {
            return false;
        }
        if (!purls.identity(policy.purl()).equals(purls.identity(finding.component().purl()))) {
            return false;
        }
        Set<String> identifiers = new LinkedHashSet<>();
        finding.identifiers().cve().forEach(value -> identifiers.add(value.toUpperCase(Locale.ROOT)));
        finding.identifiers().ghsa().forEach(value -> identifiers.add(value.toUpperCase(Locale.ROOT)));
        finding.identifiers().osv().forEach(value -> identifiers.add(value.toUpperCase(Locale.ROOT)));
        return policy.vulnerabilityIds().stream()
                .map(value -> value.toUpperCase(Locale.ROOT)).anyMatch(identifiers::contains);
    }

    private boolean applies(ProjectPolicy policy, ProjectContext project) {
        return project.manifest().modules().stream()
                .anyMatch(module -> module.path().equals(".")
                        && module.artifactId().equals(policy.projectArtifactId()));
    }

    private boolean expired(ProjectPolicy project, Instant ownExpiry, Instant now) {
        Instant expiry = effectiveExpiry(project, ownExpiry);
        return expiry != null && !expiry.isAfter(now);
    }

    private Instant effectiveExpiry(ProjectPolicy project, Instant ownExpiry) {
        if (ownExpiry == null) {
            return project.expiresAt();
        }
        if (project.expiresAt() == null) {
            return ownExpiry;
        }
        return ownExpiry.isBefore(project.expiresAt()) ? ownExpiry : project.expiresAt();
    }

    private void validate(GovernancePolicyDocument value) {
        if (value.schemaVersion() != 1) {
            throw new IllegalArgumentException("unsupported governance schemaVersion");
        }
        Set<String> ids = new LinkedHashSet<>();
        Set<String> projectIds = new LinkedHashSet<>();
        for (ProjectPolicy project : value.projects()) {
            unique(projectIds, project.id());
            requireText(project.projectArtifactId(), "projectArtifactId");
            project.reviewedFindings().forEach(set -> {
                unique(ids, set.id());
                requireAssessment(set.disposition(), set.applicability(), set.id());
                requireExpiry(project, set.expiresAt(), set.id());
                if (set.fingerprints().isEmpty() || set.fingerprints().stream()
                        .anyMatch(valueFingerprint -> !valueFingerprint.matches("sha256:[0-9a-f]{64}"))) {
                    throw new IllegalArgumentException(
                            "reviewed finding set requires valid SHA-256 fingerprints: " + set.id());
                }
                requireText(set.rationale(), "reviewed rationale");
                if (set.evidence().isEmpty()) {
                    throw new IllegalArgumentException("reviewed finding set requires evidence: " + set.id());
                }
            });
            project.dependencies().forEach(policy -> {
                unique(ids, policy.id());
                requireText(policy.purl(), "dependency policy purl");
                if (!purls.identity(policy.purl()).startsWith("pkg:maven/") || !policy.purl().contains("@")) {
                    throw new IllegalArgumentException(
                            "dependency policy requires a versioned Maven PURL: " + policy.id());
                }
                requireAssessment(policy.whenAbsentDisposition(), policy.whenAbsentApplicability(), policy.id());
                if (policy.whenAbsentApplicability() != FindingApplicability.TRIGGER_NOT_FOUND
                        && policy.whenAbsentApplicability() != FindingApplicability.NOT_AFFECTED) {
                    throw new IllegalArgumentException(
                            "dependency absence assessment must be TRIGGER_NOT_FOUND or NOT_AFFECTED: " + policy.id());
                }
                requireExpiry(project, policy.expiresAt(), policy.id());
                if (policy.vulnerabilityIds().isEmpty() || policy.triggerPatternGroups().isEmpty()
                        || policy.vulnerabilityIds().stream().anyMatch(valueId -> valueId == null || valueId.isBlank())
                        || policy.triggerPatternGroups().stream().anyMatch(group -> group.isEmpty()
                                || group.stream().anyMatch(expression -> expression == null || expression.isBlank()))) {
                    throw new IllegalArgumentException(
                            "dependency policy needs identifiers and trigger groups: " + policy.id());
                }
                policy.triggerPatternGroups().forEach(group -> group.forEach(Pattern::compile));
                requireText(policy.rationale(), "dependency rationale");
            });
        }
    }

    private void requireAssessment(
            FindingDisposition disposition, FindingApplicability applicability, String policyId) {
        if (disposition == null || applicability == null) {
            throw new IllegalArgumentException("governance policy requires disposition and applicability: " + policyId);
        }
    }

    private void requireExpiry(ProjectPolicy project, Instant ownExpiry, String policyId) {
        if (effectiveExpiry(project, ownExpiry) == null) {
            throw new IllegalArgumentException("governance policy requires an expiry: " + policyId);
        }
    }

    private void unique(Set<String> ids, String id) {
        requireText(id, "governance policy id");
        if (!ids.add(id)) throw new IllegalArgumentException("duplicate governance policy id: " + id);
    }

    private void requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
    }

    record GovernancePolicyDocument(int schemaVersion, List<ProjectPolicy> projects) {
        GovernancePolicyDocument {
            projects = projects == null ? List.of() : List.copyOf(projects);
        }
    }

    record ProjectPolicy(
            String id,
            String projectArtifactId,
            Instant expiresAt,
            List<ReviewedFindingSet> reviewedFindings,
            List<DependencyPolicy> dependencies) {
        ProjectPolicy {
            reviewedFindings = reviewedFindings == null ? List.of() : List.copyOf(reviewedFindings);
            dependencies = dependencies == null ? List.of() : List.copyOf(dependencies);
        }
    }

    record ReviewedFindingSet(
            String id,
            List<String> fingerprints,
            FindingDisposition disposition,
            FindingApplicability applicability,
            String rationale,
            List<String> evidence,
            String upstreamSeverity,
            Instant expiresAt) {
        ReviewedFindingSet {
            fingerprints = fingerprints == null ? List.of() : List.copyOf(fingerprints);
            evidence = evidence == null ? List.of() : List.copyOf(evidence);
        }
    }

    record DependencyPolicy(
            String id,
            String purl,
            List<String> vulnerabilityIds,
            List<List<String>> triggerPatternGroups,
            FindingDisposition whenAbsentDisposition,
            FindingApplicability whenAbsentApplicability,
            String upstreamSeverity,
            String rationale,
            Instant expiresAt) {
        DependencyPolicy {
            vulnerabilityIds = vulnerabilityIds == null ? List.of() : List.copyOf(vulnerabilityIds);
            triggerPatternGroups = triggerPatternGroups == null ? List.of() : triggerPatternGroups.stream()
                    .map(List::copyOf).toList();
        }
    }

    private record IndexedText(String source, String content) { }

    private static final class ProjectEvidenceIndex {
        private final List<IndexedText> values;

        private ProjectEvidenceIndex(List<IndexedText> values) {
            this.values = List.copyOf(values);
        }

        static ProjectEvidenceIndex empty() {
            return new ProjectEvidenceIndex(List.of());
        }

        static ProjectEvidenceIndex create(Path root) throws IOException {
            List<IndexedText> indexed = new ArrayList<>();
            try (var files = Files.walk(root)) {
                for (Path path : files.filter(Files::isRegularFile).toList()) {
                    String relative = root.relativize(path).toString().replace('\\', '/');
                    if (excluded(relative)) continue;
                    if (isProjectText(relative) && Files.size(path) <= MAX_TEXT_BYTES) {
                        indexed.add(new IndexedText(relative,
                                Files.readString(path, StandardCharsets.UTF_8)));
                    } else if (relative.contains("/target/") && relative.endsWith(".jar")) {
                        try (ZipFile archive = new ZipFile(path.toFile())) {
                            String entries = archive.stream().map(entry -> entry.getName()).sorted()
                                    .collect(java.util.stream.Collectors.joining("\n"));
                            indexed.add(new IndexedText(relative + "!entries", entries));
                        } catch (IOException ignored) {
                            // A malformed build artifact is not affirmative trigger evidence.
                        }
                    }
                }
            }
            return new ProjectEvidenceIndex(indexed);
        }

        List<String> matchGroups(List<List<String>> groups) {
            if (groups.isEmpty()) return List.of();
            List<String> matched = new ArrayList<>();
            for (List<String> group : groups) {
                String groupMatch = null;
                for (String expression : group) {
                    Pattern pattern = Pattern.compile(expression, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
                    for (IndexedText value : values) {
                        if (pattern.matcher(value.source() + "\n" + value.content()).find()) {
                            groupMatch = value.source() + " matches /" + expression + "/";
                            break;
                        }
                    }
                    if (groupMatch != null) break;
                }
                if (groupMatch == null) return List.of();
                matched.add(groupMatch);
            }
            return List.copyOf(matched);
        }

        private static boolean isProjectText(String relative) {
            if (relative.equals("pom.xml") || relative.endsWith("/pom.xml")) return true;
            if (!(relative.contains("/src/main/") || relative.startsWith("src/main/")
                    || relative.startsWith("config/") || relative.contains("/config/"))) return false;
            return TEXT_EXTENSIONS.stream().anyMatch(relative::endsWith);
        }

        private static boolean excluded(String relative) {
            return relative.startsWith(".git/") || relative.startsWith("dist/") || relative.startsWith("data/")
                    || relative.startsWith("tools/downloads/") || relative.endsWith("finding-governance.json");
        }
    }
}
