package io.github.uprxiao.audit.adapter.support;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.uprxiao.audit.finding.ComponentEvidence;
import io.github.uprxiao.audit.finding.Confidence;
import io.github.uprxiao.audit.finding.Finding;
import io.github.uprxiao.audit.finding.FindingEvidence;
import io.github.uprxiao.audit.finding.FindingFingerprintService;
import io.github.uprxiao.audit.finding.IssueCategory;
import io.github.uprxiao.audit.finding.ReviewState;
import io.github.uprxiao.audit.finding.SeverityMappingRequest;
import io.github.uprxiao.audit.finding.SeverityMappingResult;
import io.github.uprxiao.audit.finding.SeverityMappingService;
import io.github.uprxiao.audit.finding.VulnerabilityIdentifiers;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Shared strict V1 dependency-vulnerability mapping. */
public final class DependencyFindingSupport {

    private final FindingFingerprintService fingerprints = new FindingFingerprintService();
    private final SeverityMappingService severities = new SeverityMappingService();

    public Finding finding(
            String engine,
            String version,
            String rawArtifact,
            String rawItemId,
            String vulnerabilityId,
            List<String> aliases,
            List<String> cwes,
            String purl,
            String packageName,
            String currentVersion,
            String module,
            String scope,
            boolean direct,
            List<String> dependencyPath,
            List<String> fixedVersions,
            String engineSeverity,
            Double cvss,
            boolean knownExploited,
            String title,
            String description,
            Map<String, Object> extraProperties) {
        String completePurl = completePurl(purl, packageName, currentVersion);
        Coordinates coordinates = coordinates(completePurl, packageName);
        VulnerabilityIdentifiers identifiers = identifiers(vulnerabilityId, aliases, cwes);
        String canonicalId = canonicalId(vulnerabilityId, identifiers);
        ComponentEvidence component = new ComponentEvidence(
                completePurl, coordinates.groupId(), coordinates.artifactId(), required(currentVersion, "currentVersion"),
                scope == null ? "" : scope, direct, distinct(dependencyPath), distinct(fixedVersions));
        FindingFingerprintService.Fingerprint fingerprint = fingerprints.dependency(canonicalId, completePurl, module);
        SeverityMappingResult severity = severities.map(new SeverityMappingRequest(
                engine, "DEPENDENCY_VULNERABILITY", IssueCategory.DEPENDENCY_VULNERABILITY,
                engineSeverity == null ? "" : engineSeverity, cvss, knownExploited, false, Confidence.HIGH));
        Map<String, Object> properties = new LinkedHashMap<>();
        if (extraProperties != null) properties.putAll(extraProperties);
        properties.put("severityMappingId", severity.mappingId());
        properties.put("severityMappingReason", severity.reason());
        properties.put("currentVersion", currentVersion);
        properties.put("fixedVersions", distinct(fixedVersions));
        properties.put("dependencyPath", distinct(dependencyPath));
        properties.put("purl", completePurl);
        properties.put("knownExploited", knownExploited);
        if (cvss != null) properties.put("cvss", cvss);
        FindingEvidence evidence = new FindingEvidence(
                engine, version, vulnerabilityId, engineSeverity, rawArtifact, rawItemId, properties);
        String safeTitle = title == null || title.isBlank() ? vulnerabilityId : title;
        return new Finding(
                fingerprint.findingId(), fingerprint.value(), fingerprint.version(),
                IssueCategory.DEPENDENCY_VULNERABILITY, severity.severity(), Confidence.HIGH,
                "DEPENDENCY_VULNERABILITY", "依赖组件存在已知漏洞：" + vulnerabilityId, safeTitle,
                description == null ? "" : description, safeTitle,
                "受影响组件可能导致保密性、完整性或可用性风险。",
                distinct(fixedVersions).isEmpty()
                        ? "结合上游公告、实际可达性和风险接受策略复核。"
                        : "升级至已修复版本之一：" + String.join("、", distinct(fixedVersions)) + "。",
                module == null ? "" : module, null, null, identifiers, component,
                List.of(), List.of(evidence), null, ReviewState.UNREVIEWED);
    }

    public static List<String> strings(JsonNode node) {
        if (node == null || !node.isArray()) return List.of();
        List<String> result = new ArrayList<>();
        node.forEach(value -> {
            String text = value.asText("").trim();
            if (!text.isBlank()) result.add(text);
        });
        return distinct(result);
    }

    public static List<String> fixedVersions(JsonNode vulnerability) {
        List<String> result = new ArrayList<>();
        vulnerability.path("affected").forEach(affected -> affected.path("ranges").forEach(range ->
                range.path("events").forEach(event -> {
                    String fixed = event.path("fixed").asText("").trim();
                    if (!fixed.isBlank()) result.add(fixed);
                })));
        return distinct(result);
    }

    public static Double decimal(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) return null;
        if (node.isNumber()) return node.asDouble();
        String value = node.asText("").trim();
        if (value.isBlank()) return null;
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    public static List<String> distinct(List<String> values) {
        if (values == null) return List.of();
        LinkedHashSet<String> unique = new LinkedHashSet<>();
        values.stream().filter(value -> value != null && !value.isBlank()).map(String::trim).forEach(unique::add);
        return List.copyOf(unique);
    }

    private VulnerabilityIdentifiers identifiers(String id, List<String> aliases, List<String> cwes) {
        List<String> all = new ArrayList<>();
        all.add(required(id, "vulnerabilityId"));
        if (aliases != null) all.addAll(aliases);
        List<String> cve = new ArrayList<>();
        List<String> ghsa = new ArrayList<>();
        List<String> osv = new ArrayList<>();
        for (String value : distinct(all)) {
            String upper = value.toUpperCase(Locale.ROOT);
            if (upper.startsWith("CVE-")) cve.add(upper);
            else if (upper.startsWith("GHSA-")) ghsa.add(upper);
            else osv.add(value);
        }
        return new VulnerabilityIdentifiers(distinct(cwes), distinct(cve), distinct(ghsa), distinct(osv));
    }

    private String canonicalId(String requested, VulnerabilityIdentifiers identifiers) {
        if (!identifiers.cve().isEmpty()) return identifiers.cve().get(0);
        if (!identifiers.ghsa().isEmpty()) return identifiers.ghsa().get(0);
        if (!identifiers.osv().isEmpty()) return identifiers.osv().get(0);
        return requested;
    }

    private String completePurl(String purl, String packageName, String version) {
        String candidate = purl == null ? "" : purl.trim();
        if (candidate.isBlank()) {
            String[] parts = required(packageName, "packageName").split(":", 2);
            if (parts.length != 2) throw new IllegalArgumentException("Maven package name must be groupId:artifactId");
            candidate = "pkg:maven/" + parts[0] + "/" + parts[1];
        }
        if (!candidate.startsWith("pkg:")) throw new IllegalArgumentException("invalid PURL: " + candidate);
        return candidate.contains("@") ? candidate : candidate + "@" + required(version, "currentVersion");
    }

    private Coordinates coordinates(String purl, String packageName) {
        if (!purl.startsWith("pkg:maven/")) {
            throw new IllegalArgumentException("V1 Java supply adapters require a Maven PURL: " + purl);
        }
        String withoutScheme = purl.substring("pkg:maven/".length());
        String identity = withoutScheme.split("[@?]", 2)[0];
        String[] path = identity.split("/", 2);
        if (path.length == 2) return new Coordinates(path[0], path[1]);
        String[] name = required(packageName, "packageName").split(":", 2);
        if (name.length == 2) return new Coordinates(name[0], name[1]);
        return new Coordinates("", packageName);
    }

    private String required(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
        return value.trim();
    }

    private record Coordinates(String groupId, String artifactId) { }
}
