package io.github.uprxiao.audit.finding;

import java.util.List;
import java.util.Objects;

public record ComponentEvidence(
        String purl,
        String groupId,
        String artifactId,
        String version,
        String scope,
        boolean direct,
        List<String> dependencyPath,
        List<String> fixedVersions) {

    public ComponentEvidence {
        Objects.requireNonNull(purl, "purl");
        if (!purl.startsWith("pkg:")) {
            throw new IllegalArgumentException("component purl must start with pkg:");
        }
        Objects.requireNonNull(groupId, "groupId");
        Objects.requireNonNull(artifactId, "artifactId");
        Objects.requireNonNull(version, "version");
        dependencyPath = dependencyPath == null ? List.of() : List.copyOf(dependencyPath);
        fixedVersions = fixedVersions == null ? List.of() : List.copyOf(fixedVersions);
    }
}
